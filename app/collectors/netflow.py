"""Network flow collector. Parses a directory of flow records below SCAN_ROOT:

  zeek    conn.log in JSON-lines form (fields ts, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
          proto, service, duration, orig_bytes, resp_bytes, conn_state)
  nfdump  `nfdump -o json` output (t_first, src4_addr/src6_addr, dst4_addr, src_port, dst_port,
          proto, in_bytes/out_bytes, in_packets)
  generic objects with src/dst/sport/dport/bytes/ts keys

Builds `network` nodes for internal hosts and external IPs with aggregated `connects_to` edges,
and emits events for beaconing (regular intervals from one internal host to one external IP)
and large egress volumes. No network calls are made; this collector only reads files.
"""
from __future__ import annotations

import asyncio
import json
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import Collector, CollectorContext, CollectorResult, is_private_ip, parse_time, registry

log = logging.getLogger('argus.collectors.netflow')

SENSITIVE_PORTS = {22: 'ssh', 23: 'telnet', 3389: 'rdp', 445: 'smb', 1433: 'mssql', 3306: 'mysql', 5432: 'postgres', 6379: 'redis', 27017: 'mongodb', 4444: 'metasploit',
                   1337: 'leet', 6667: 'irc', 9001: 'tor', 9030: 'tor', 25: 'smtp', 53: 'dns', 443: 'https', 80: 'http'}
MAX_FLOWS = 2_000_000


class NetflowCollector(Collector):
    name = 'netflow'
    kind = 'network'
    description = 'NetFlow / Zeek conn.log directory: internal hosts, external destinations, connects_to edges, beaconing and large-egress events.'
    sdk_modules = ()
    secret_fields: list[str] = []
    default_schedule_minutes = 60
    config_schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['path'],
        'properties': {
            'path': {'type': 'string', 'maxLength': 512, 'description': 'Directory of flow files, relative to SCAN_ROOT'},
            'format': {'type': 'string', 'enum': ['auto', 'zeek', 'nfdump', 'generic']},
            'internal_cidrs': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Extra CIDRs treated as internal (public ranges you own)'},
            'beacon_min_connections': {'type': 'integer', 'minimum': 4, 'maximum': 100000},
            'beacon_max_jitter': {'type': 'number', 'minimum': 0.01, 'maximum': 1.0, 'description': 'Coefficient of variation of inter-arrival times; default 0.2'},
            'egress_threshold_mb': {'type': 'number', 'minimum': 1},
            'site': {'type': 'string', 'maxLength': 80, 'description': 'Label for this sensor location'},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        directory = _resolve_dir(ctx)
        raw = await asyncio.to_thread(_read_flows, directory, ctx.config, ctx.logger)
        raw['config'] = {k: ctx.config.get(k) for k in ('internal_cidrs', 'beacon_min_connections', 'beacon_max_jitter', 'egress_threshold_mb', 'site')}
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        cfg = raw.get('config') or {}
        internal_cidrs = list(cfg.get('internal_cidrs') or [])
        min_conns = int(cfg.get('beacon_min_connections') or 8)
        max_jitter = float(cfg.get('beacon_max_jitter') or 0.2)
        egress_bytes = float(cfg.get('egress_threshold_mb') or 500) * 1024 * 1024
        site = cfg.get('site') or 'default'
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        flows = raw.get('flows') or []
        pairs: dict[tuple[str, str], dict[str, Any]] = {}
        internal_hosts: dict[str, dict[str, Any]] = {}
        external_hosts: dict[str, dict[str, Any]] = {}
        internal_count = external_count = 0
        for flow in flows:
            src, dst = str(flow.get('src') or ''), str(flow.get('dst') or '')
            if not src or not dst:
                continue
            src_internal, dst_internal = is_private_ip(src, internal_cidrs), is_private_ip(dst, internal_cidrs)
            if src_internal and dst_internal:
                internal_count += 1
                continue  # east-west traffic is kept out of the graph to bound its size
            if not src_internal and not dst_internal:
                continue
            external_count += 1
            ts = parse_time(flow.get('ts'))
            dport = _int(flow.get('dport'))
            out_bytes = _int(flow.get('orig_bytes')) or 0
            in_bytes = _int(flow.get('resp_bytes')) or 0
            if src_internal:
                internal_hosts.setdefault(src, {'out_bytes': 0, 'destinations': set()})
                internal_hosts[src]['out_bytes'] += out_bytes
                internal_hosts[src]['destinations'].add(dst)
                external_hosts.setdefault(dst, {'in_bytes': 0, 'sources': set(), 'ports': set()})
                external_hosts[dst]['sources'].add(src)
                external_hosts[dst]['in_bytes'] += out_bytes
                if dport:
                    external_hosts[dst]['ports'].add(dport)
                direction = 'outbound'
            else:
                internal_hosts.setdefault(dst, {'out_bytes': 0, 'destinations': set(), 'inbound_from': set(), 'inbound_ports': set()})
                internal_hosts[dst].setdefault('inbound_from', set()).add(src)
                if dport:
                    internal_hosts[dst].setdefault('inbound_ports', set()).add(dport)
                external_hosts.setdefault(src, {'in_bytes': 0, 'sources': set(), 'ports': set()})
                direction = 'inbound'
            pair = pairs.setdefault((src, dst), {'count': 0, 'bytes_out': 0, 'bytes_in': 0, 'ports': set(), 'timestamps': [], 'protocols': set(), 'services': set(),
                                                 'direction': direction, 'first': None, 'last': None})
            pair['count'] += 1
            pair['bytes_out'] += out_bytes
            pair['bytes_in'] += in_bytes
            if dport:
                pair['ports'].add(dport)
            if flow.get('proto'):
                pair['protocols'].add(str(flow['proto']).lower())
            if flow.get('service'):
                pair['services'].add(str(flow['service']))
            if ts is not None:
                pair['timestamps'].append(ts.timestamp())
                pair['first'] = ts if pair['first'] is None or ts < pair['first'] else pair['first']
                pair['last'] = ts if pair['last'] is None or ts > pair['last'] else pair['last']

        site_node = r.node('network', f'netflow:site:{site}', {'provider': 'netflow', 'type': 'sensor_site', 'site': site, 'flows_total': len(flows),
                                                                'flows_internal': internal_count, 'flows_external': external_count}, label=f'Flow sensor {site}', criticality='low')
        for ip, info in internal_hosts.items():
            node = r.node('network', f'ip:{ip}', {'provider': 'netflow', 'type': 'internal_host', 'ip': ip, 'bytes_out': info['out_bytes'], 'external_destinations': len(info['destinations']),
                                                  'inbound_sources': len(info.get('inbound_from') or ()), 'inbound_ports': sorted(info.get('inbound_ports') or ())[:50]},
                          label=ip, criticality='medium')
            r.edge(site_node, node, 'owns')
            if info.get('inbound_from'):
                exposure = r.node('exposure', f'netflow:exposure:{ip}', {'type': 'inbound_from_internet', 'ports': sorted(info.get('inbound_ports') or ())[:50],
                                                                        'sources': len(info['inbound_from'])}, label=f'{ip} reachable from Internet', criticality='high')
                r.edge(node, exposure, 'exposes')
            if info['out_bytes'] > egress_bytes:
                top = max(((d, pairs[(ip, d)]['bytes_out']) for d in info['destinations'] if (ip, d) in pairs), key=lambda x: x[1], default=(None, 0))
                r.event(source, f'netflow:{site}:egress:{ip}:{int(info["out_bytes"] // (256 * 1024 * 1024))}', f'{ip} sent {info["out_bytes"] / 1048576:.0f} MB to external hosts',
                        'high' if info['out_bytes'] > 4 * egress_bytes else 'medium', 'network', actor=ip, entity=top[0] or '', action='large_egress',
                        metadata={'bytes_out': info['out_bytes'], 'destinations': len(info['destinations']), 'top_destination': top[0], 'top_destination_bytes': top[1], 'site': site})
        for ip, info in external_hosts.items():
            r.node('network', f'ip:{ip}', {'provider': 'netflow', 'type': 'external_host', 'ip': ip, 'bytes_received': info['in_bytes'], 'internal_sources': len(info['sources']),
                                           'ports': sorted(info['ports'])[:50]}, label=ip, criticality='low')
        beacons = 0
        for (src, dst), pair in pairs.items():
            sensitive = sorted({SENSITIVE_PORTS[p] for p in pair['ports'] if p in SENSITIVE_PORTS and p not in (80, 443, 53)})
            edge_props = {'count': pair['count'], 'bytes_out': pair['bytes_out'], 'bytes_in': pair['bytes_in'], 'ports': sorted(pair['ports'])[:20], 'protocols': sorted(pair['protocols']),
                          'services': sorted(pair['services'])[:10], 'direction': pair['direction'], 'first_seen': pair['first'].isoformat() if pair['first'] else None,
                          'last_seen': pair['last'].isoformat() if pair['last'] else None, 'sensitive_services': sensitive}
            beacon = _beacon_score(pair['timestamps'], min_conns, max_jitter)
            if beacon is not None:
                edge_props['beacon'] = beacon
            r.edge(('network', f'ip:{src}'), ('network', f'ip:{dst}'), 'connects_to', edge_props)
            if beacon is not None and pair['direction'] == 'outbound':
                beacons += 1
                r.event(source, f"netflow:{site}:beacon:{src}:{dst}:{int(beacon['interval_seconds'])}", f"{src} beacons to {dst} every {beacon['interval_seconds']:.0f}s ({pair['count']} connections)",
                        'high', 'network', actor=src, entity=dst, action='beaconing', occurred_at=pair['last'],
                        metadata={'interval_seconds': beacon['interval_seconds'], 'jitter': beacon['jitter'], 'connections': pair['count'], 'ports': sorted(pair['ports'])[:10],
                                  'bytes_out': pair['bytes_out'], 'bytes_in': pair['bytes_in'], 'site': site})
            if pair['direction'] == 'inbound' and sensitive:
                r.event(source, f'netflow:{site}:inbound-sensitive:{dst}:{src}:{",".join(sensitive)}', f'{src} reached {dst} on {", ".join(sensitive)} from the Internet',
                        'medium', 'network', actor=src, entity=dst, action='inbound_sensitive_service', occurred_at=pair['last'],
                        metadata={'services': sensitive, 'ports': sorted(pair['ports'])[:10], 'connections': pair['count'], 'site': site})
        r.stats.update({'flows': len(flows), 'flows_internal': internal_count, 'flows_external': external_count, 'internal_hosts': len(internal_hosts),
                        'external_hosts': len(external_hosts), 'pairs': len(pairs), 'beacons': beacons, 'files': raw.get('files', 0)})
        return r.finalize()


def _int(value: Any) -> int | None:
    try:
        return int(float(value)) if value not in (None, '', '-') else None
    except (TypeError, ValueError):
        return None


def _beacon_score(timestamps: list[float], min_conns: int, max_jitter: float) -> dict[str, Any] | None:
    if len(timestamps) < min_conns:
        return None
    ordered = sorted(timestamps)
    intervals = [b - a for a, b in zip(ordered, ordered[1:]) if b - a > 0]
    if len(intervals) < min_conns - 1:
        return None
    mean = statistics.fmean(intervals)
    if mean < 1:
        return None
    stdev = statistics.pstdev(intervals)
    jitter = stdev / mean
    if jitter > max_jitter:
        # Tolerate a few outliers (missed beacons, bursts): look at the interquartile core.
        core = sorted(intervals)[len(intervals) // 4: max(len(intervals) // 4 + 1, 3 * len(intervals) // 4)]
        if len(core) < 3:
            return None
        mean, stdev = statistics.fmean(core), statistics.pstdev(core)
        jitter = stdev / mean if mean else 1.0
        if jitter > max_jitter:
            return None
    return {'interval_seconds': round(mean, 1), 'jitter': round(jitter, 3), 'samples': len(intervals)}


# ---------------------------------------------------------------- file parsing


def _resolve_dir(ctx: CollectorContext) -> Path:
    root = Path(ctx.settings.scan_root).resolve()
    rel = str(ctx.config.get('path') or '').strip()
    target = (root / rel).resolve()
    if root != target and root not in target.parents:
        raise ValueError('netflow path must be inside SCAN_ROOT')
    return target


def _read_flows(directory: Path, config: dict[str, Any], logger: logging.Logger) -> dict[str, Any]:
    warnings: list[str] = []
    flows: list[dict[str, Any]] = []
    if not directory.is_dir():
        return {'flows': [], 'warnings': [f'directory not found: {directory.name}'], 'files': 0}
    fmt = config.get('format') or 'auto'
    files = sorted(p for p in directory.rglob('*') if p.is_file() and p.suffix.lower() in ('.log', '.json', '.jsonl', '.ndjson'))
    for path in files:
        try:
            with path.open('r', encoding='utf-8', errors='replace') as fh:
                head = fh.read(2)
                fh.seek(0)
                if head.lstrip().startswith('['):
                    try:
                        records = json.load(fh)
                    except ValueError:
                        warnings.append(f'{path.name}: invalid JSON')
                        continue
                    for record in records if isinstance(records, list) else []:
                        flow = normalize_flow(record, fmt)
                        if flow:
                            flows.append(flow)
                else:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        try:
                            record = json.loads(line)
                        except ValueError:
                            continue
                        flow = normalize_flow(record, fmt)
                        if flow:
                            flows.append(flow)
                        if len(flows) >= MAX_FLOWS:
                            warnings.append(f'flow cap of {MAX_FLOWS} reached')
                            break
        except OSError as exc:
            warnings.append(f'{path.name}: {type(exc).__name__}')
        if len(flows) >= MAX_FLOWS:
            break
    return {'flows': flows, 'warnings': warnings, 'files': len(files)}


def normalize_flow(record: Any, fmt: str = 'auto') -> dict[str, Any] | None:
    """Map a zeek / nfdump / generic record to {ts, src, sport, dst, dport, proto, service, orig_bytes, resp_bytes}."""
    if not isinstance(record, dict):
        return None
    if fmt in ('auto', 'zeek') and 'id.orig_h' in record:
        return {'ts': record.get('ts'), 'src': record.get('id.orig_h'), 'sport': record.get('id.orig_p'), 'dst': record.get('id.resp_h'), 'dport': record.get('id.resp_p'),
                'proto': record.get('proto'), 'service': record.get('service'), 'orig_bytes': record.get('orig_bytes') or record.get('orig_ip_bytes') or 0,
                'resp_bytes': record.get('resp_bytes') or record.get('resp_ip_bytes') or 0, 'state': record.get('conn_state'), 'duration': record.get('duration')}
    if fmt in ('auto', 'zeek') and isinstance(record.get('id'), dict):
        ident = record['id']
        return {'ts': record.get('ts'), 'src': ident.get('orig_h'), 'sport': ident.get('orig_p'), 'dst': ident.get('resp_h'), 'dport': ident.get('resp_p'), 'proto': record.get('proto'),
                'service': record.get('service'), 'orig_bytes': record.get('orig_bytes') or 0, 'resp_bytes': record.get('resp_bytes') or 0, 'state': record.get('conn_state')}
    if fmt in ('auto', 'nfdump') and ('src4_addr' in record or 'src6_addr' in record):
        return {'ts': record.get('t_first') or record.get('first'), 'src': record.get('src4_addr') or record.get('src6_addr'), 'sport': record.get('src_port'),
                'dst': record.get('dst4_addr') or record.get('dst6_addr'), 'dport': record.get('dst_port'), 'proto': record.get('proto'), 'service': None,
                'orig_bytes': record.get('in_bytes') or 0, 'resp_bytes': record.get('out_bytes') or 0, 'state': record.get('tcp_flags')}
    if fmt in ('auto', 'generic') and ('src' in record or 'src_ip' in record or 'source.ip' in record):
        return {'ts': record.get('ts') or record.get('timestamp') or record.get('@timestamp'), 'src': record.get('src') or record.get('src_ip') or record.get('source.ip'),
                'sport': record.get('sport') or record.get('src_port'), 'dst': record.get('dst') or record.get('dst_ip') or record.get('destination.ip'),
                'dport': record.get('dport') or record.get('dst_port'), 'proto': record.get('proto') or record.get('protocol'), 'service': record.get('service'),
                'orig_bytes': record.get('bytes_out') or record.get('orig_bytes') or record.get('bytes') or 0, 'resp_bytes': record.get('bytes_in') or record.get('resp_bytes') or 0}
    return None


registry.register(NetflowCollector())
