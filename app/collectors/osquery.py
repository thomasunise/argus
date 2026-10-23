"""osquery fleet collector. Two read-only sources:

  mode=fleet      FleetDM REST API with an API-only user token:
                    GET /api/v1/fleet/hosts?per_page=100&page=N
                    GET /api/v1/fleet/hosts/{id}            (software, users, primary IP, OS)
                    GET /api/v1/fleet/queries/{id}/report   (query reports for listening ports,
                                                             sudoers, processes; ids come from config)
  mode=directory  osquery result logs (JSON lines, `--logger_plugin=filesystem` format) in a
                  directory below SCAN_ROOT. Recognised query names (suffix match):
                    listening_ports, users, sudoers, installed_packages | deb_packages | rpm_packages |
                    programs | homebrew_packages | python_packages, processes, system_info, os_version

Emits host assets, listening-port exposures, users with sudo, installed packages (as props; vuln
matching happens in the detections package) and processes with suspicious parents as events.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import httpx

from .base import Collector, CollectorContext, CollectorResult, is_private_ip, parse_time, registry

log = logging.getLogger('sentinel.collectors.osquery')

SERVER_PARENTS = {'nginx', 'apache2', 'httpd', 'java', 'tomcat', 'node', 'php-fpm', 'w3wp.exe', 'sqlservr.exe', 'postgres', 'mysqld', 'mongod', 'redis-server',
                  'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'acrord32.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe'}
SHELL_CHILDREN = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'pwsh', 'nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'python', 'python3',
                  'perl', 'ruby', 'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'wmic.exe', 'telnet', 'base64'}
SENSITIVE_PORTS = {22: 'ssh', 23: 'telnet', 21: 'ftp', 3389: 'rdp', 5900: 'vnc', 445: 'smb', 139: 'netbios', 3306: 'mysql', 5432: 'postgres', 1433: 'mssql', 27017: 'mongodb',
                   6379: 'redis', 9200: 'elasticsearch', 11211: 'memcached', 2375: 'docker', 5985: 'winrm', 5986: 'winrm', 10250: 'kubelet', 2379: 'etcd'}
PACKAGE_QUERIES = ('installed_packages', 'deb_packages', 'rpm_packages', 'programs', 'homebrew_packages', 'python_packages', 'chocolatey_packages', 'apt_sources')


class OsqueryCollector(Collector):
    name = 'osquery'
    kind = 'endpoint'
    description = 'osquery fleet results (FleetDM API or result-log directory): hosts, listening ports, sudo users, installed packages, processes with suspicious parents.'
    sdk_modules = ('httpx',)
    secret_fields = ['fleet_token']
    default_schedule_minutes = 60
    config_schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'mode': {'type': 'string', 'enum': ['fleet', 'directory'], 'description': 'default directory'},
            'fleet_url': {'type': 'string', 'pattern': r'^https?://'},
            'query_reports': {'type': 'object', 'additionalProperties': False, 'description': 'FleetDM query ids with reports enabled',
                              'properties': {'listening_ports': {'type': 'integer'}, 'sudoers': {'type': 'integer'}, 'processes': {'type': 'integer'}, 'users': {'type': 'integer'}}},
            'path': {'type': 'string', 'maxLength': 512, 'description': 'Directory of osquery result logs, relative to SCAN_ROOT'},
            'max_hosts': {'type': 'integer', 'minimum': 1, 'maximum': 100000},
        },
    }

    async def collect(self, ctx: CollectorContext) -> CollectorResult:
        mode = ctx.config.get('mode') or 'directory'
        if mode == 'fleet':
            raw = await _fetch_fleet(ctx)
        else:
            raw = await asyncio.to_thread(_read_directory, _resolve_dir(ctx), ctx.logger)
        return self._normalize(raw)

    def _normalize(self, raw: dict[str, Any]) -> CollectorResult:
        r = CollectorResult()
        source = self.source
        counts = {'hosts': 0, 'listening_ports': 0, 'sudo_users': 0, 'packages': 0, 'suspicious_processes': 0}
        for warning in raw.get('warnings', []) or []:
            r.warn(str(warning))
        for host in raw.get('hosts', []) or []:
            ident = str(host.get('identifier') or host.get('hostname') or '')
            if not ident:
                continue
            hostname = host.get('hostname') or ident
            ips = [ip for ip in [host.get('primary_ip')] + list(host.get('ips') or []) if ip]
            platform = host.get('platform') or ''
            packages = host.get('packages') or []
            counts['hosts'] += 1
            counts['packages'] += len(packages)
            hnode = r.node('asset', f'host:{ident}', {'provider': 'osquery', 'type': 'host', 'hostname': hostname, 'platform': platform, 'os_version': host.get('os_version'),
                                                      'ips': ips, 'osquery_version': host.get('osquery_version'), 'last_seen': host.get('last_seen'),
                                                      'packages': [{'name': p.get('name'), 'version': p.get('version'), 'source': p.get('source')} for p in packages[:500]],
                                                      'package_count': len(packages), 'uptime': host.get('uptime')}, label=hostname,
                           criticality='medium')
            for ip in ips:
                if ip and not is_private_ip(ip):
                    hnode.props['public_ip'] = ip
                    hnode.criticality = 'high'
            for port in host.get('listening_ports') or []:
                try:
                    pnum = int(port.get('port', 0))
                except (TypeError, ValueError):
                    continue
                if pnum <= 0:
                    continue
                address = str(port.get('address') or '0.0.0.0')  # nosec B104
                proto = str(port.get('protocol') or '6')
                proto_name = {'6': 'tcp', '17': 'udp'}.get(proto, proto)
                if address in ('127.0.0.1', '::1', 'localhost') or proto_name == 'udp' and pnum > 10000:
                    continue
                counts['listening_ports'] += 1
                service = SENSITIVE_PORTS.get(pnum)
                exposure = r.node('exposure', f'host:{ident}:port:{proto_name}/{pnum}', {'type': 'listening_port', 'port': pnum, 'protocol': proto_name, 'address': address,
                                                                                       'process': port.get('name') or port.get('path'), 'pid': port.get('pid'), 'service': service},
                                  label=f'{hostname} {proto_name}/{pnum}' + (f' ({service})' if service else ''), criticality='high' if service else 'low')
                r.edge(hnode, exposure, 'exposes')
            sudoers = host.get('sudoers') or []
            sudo_names = {str(s.get('username') or s.get('header', '')).lstrip('%') for s in sudoers if s.get('rule_details', 'ALL') or True}
            admin_groups = {'sudo', 'wheel', 'admin', 'administrators', 'root'}
            for user in host.get('users') or []:
                username = str(user.get('username') or '')
                if not username:
                    continue
                groups = set(str(g).lower() for g in user.get('groups') or [])
                uid = user.get('uid')
                try:
                    uid_num = int(uid) if uid is not None else None
                except (TypeError, ValueError):
                    uid_num = None
                is_admin = username in sudo_names or bool(groups & admin_groups) or uid_num == 0 or bool(user.get('admin'))
                if uid_num is not None and 0 < uid_num < 1000 and username not in sudo_names and 'windows' not in platform:
                    continue  # system accounts
                unode = r.node('identity', f'host:{ident}:user:{username}', {'provider': 'osquery', 'type': 'local_user', 'username': username, 'uid': uid, 'shell': user.get('shell'),
                                                                             'sudo': is_admin, 'groups': sorted(groups)[:20]}, label=f'{username}@{hostname}',
                               criticality='high' if is_admin else 'low')
                r.edge(hnode, unode, 'owns')
                if is_admin:
                    counts['sudo_users'] += 1
                    perm = r.node('permission', f'host:{ident}:sudo', {'provider': 'osquery', 'role': 'sudo', 'admin': True, 'wildcard': True, 'host': hostname}, label=f'sudo on {hostname}',
                                  criticality='high')
                    r.edge(unode, perm, 'has_permission')
            for proc in host.get('processes') or []:
                name = str(proc.get('name') or '').lower()
                parent = str(proc.get('parent_name') or '').lower()
                if parent in SERVER_PARENTS and name in SHELL_CHILDREN:
                    counts['suspicious_processes'] += 1
                    pid = proc.get('pid')
                    r.event(source, f'osquery:{ident}:proc:{pid}:{name}:{proc.get("start_time") or ""}', f'{hostname}: {parent} spawned {name}', 'high', 'process',
                            actor=str(proc.get('username') or proc.get('uid') or ''), entity=hostname, action='suspicious_child_process',
                            occurred_at=parse_time(proc.get('start_time')) if proc.get('start_time') else None,
                            metadata={'host': ident, 'pid': pid, 'parent_pid': proc.get('parent'), 'parent_name': parent, 'process': name,
                                      'cmdline': str(proc.get('cmdline') or '')[:300], 'path': proc.get('path')})
        r.stats.update(counts)
        return r.finalize()


# ---------------------------------------------------------------- directory source


def _resolve_dir(ctx: CollectorContext) -> Path:
    root = Path(ctx.settings.scan_root).resolve()
    rel = str(ctx.config.get('path') or '').strip()
    target = (root / rel).resolve() if rel else root
    if root != target and root not in target.parents:
        raise ValueError('osquery path must be inside SCAN_ROOT')
    return target


def _read_directory(directory: Path, logger: logging.Logger) -> dict[str, Any]:
    warnings: list[str] = []
    hosts: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        return {'hosts': [], 'warnings': [f'directory not found: {directory.name}']}
    files = sorted(p for p in directory.rglob('*') if p.is_file() and p.suffix.lower() in ('.json', '.log', '.jsonl'))
    for path in files:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError as exc:
            warnings.append(f'{path.name}: {type(exc).__name__}')
            continue
        records: list[Any] = []
        stripped = text.lstrip()
        if stripped.startswith('['):
            try:
                records = json.loads(stripped)
            except ValueError:
                warnings.append(f'{path.name}: invalid JSON array')
                continue
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
        for record in records:
            if isinstance(record, dict):
                _ingest_record(hosts, record)
    return {'hosts': list(hosts.values()), 'warnings': warnings, 'files': len(files)}


def _ingest_record(hosts: dict[str, dict[str, Any]], record: dict[str, Any]) -> None:
    ident = str(record.get('hostIdentifier') or record.get('host_identifier') or record.get('hostname') or '')
    if not ident:
        return
    host = hosts.setdefault(ident, {'identifier': ident, 'hostname': record.get('hostname') or ident, 'listening_ports': [], 'users': [], 'sudoers': [], 'packages': [],
                                    'processes': [], 'platform': '', 'os_version': None, 'ips': []})
    name = str(record.get('name') or '').lower()
    rows: list[dict[str, Any]] = []
    if isinstance(record.get('columns'), dict):
        if record.get('action', 'added') == 'removed':
            return
        rows = [record['columns']]
    elif isinstance(record.get('snapshot'), list):
        rows = [r for r in record['snapshot'] if isinstance(r, dict)]
    elif isinstance(record.get('diffResults'), dict):
        rows = [r for r in record['diffResults'].get('added', []) if isinstance(r, dict)]
    decorations = record.get('decorations') or {}
    if decorations.get('hostname'):
        host['hostname'] = decorations['hostname']
    if decorations.get('host_uuid'):
        host['uuid'] = decorations['host_uuid']
    if decorations.get('platform'):
        host['platform'] = decorations['platform']
    for row in rows:
        if name.endswith('listening_ports'):
            host['listening_ports'].append(row)
        elif name.endswith('sudoers'):
            host['sudoers'].append(row)
        elif name.endswith('users') or name.endswith('user_groups_joined'):
            groups = row.get('groups')
            if isinstance(groups, str):
                row['groups'] = [g for g in groups.split(',') if g]
            host['users'].append(row)
        elif any(name.endswith(q) for q in PACKAGE_QUERIES):
            host['packages'].append({'name': row.get('name'), 'version': row.get('version'), 'source': name.rsplit('_', 2)[-2] if '_' in name else name})
        elif name.endswith('processes'):
            host['processes'].append(row)
        elif name.endswith('system_info'):
            host['hostname'] = row.get('hostname') or row.get('computer_name') or host['hostname']
            host['hardware'] = row.get('hardware_model')
            host['uuid'] = row.get('uuid') or host.get('uuid')
        elif name.endswith('os_version'):
            host['platform'] = row.get('platform') or host['platform']
            host['os_version'] = f"{row.get('name', '')} {row.get('version', '')}".strip()
        elif name.endswith('interface_addresses'):
            addr = row.get('address')
            if addr and not str(addr).startswith(('127.', '::1', 'fe80')):
                host['ips'].append(addr)
                host.setdefault('primary_ip', addr)
        elif name.endswith('osquery_info'):
            host['osquery_version'] = row.get('version')


# ---------------------------------------------------------------- FleetDM source


async def _fetch_fleet(ctx: CollectorContext) -> dict[str, Any]:
    config = ctx.config
    base = str(config.get('fleet_url') or '').rstrip('/')
    if not base:
        raise ValueError('fleet_url is required for mode=fleet')
    from ..integrations.egress import egress_ok

    denied = egress_ok(base, ctx.settings, allow_http=bool(getattr(ctx.settings, 'allow_private_targets', False)))
    if denied:
        raise ValueError(f'fleet_url refused: {denied}')
    headers = {'Accept': 'application/json', 'User-Agent': 'sentinel-collector'}
    if config.get('fleet_token'):
        headers['Authorization'] = f"Bearer {config['fleet_token']}"
    warnings: list[str] = []
    hosts: dict[int, dict[str, Any]] = {}
    max_hosts = int(config.get('max_hosts') or 5000)
    async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(30.0), follow_redirects=False, trust_env=False) as client:
        page = 0
        while len(hosts) < max_hosts:
            response = await client.get(f'{base}/api/v1/fleet/hosts', params={'per_page': 100, 'page': page})
            response.raise_for_status()
            batch = response.json().get('hosts', [])
            if not batch:
                break
            for h in batch:
                hosts[h['id']] = {'identifier': h.get('uuid') or h.get('hostname') or str(h['id']), 'fleet_id': h['id'], 'hostname': h.get('hostname'), 'platform': h.get('platform'),
                                  'os_version': h.get('os_version'), 'primary_ip': h.get('primary_ip'), 'ips': [], 'osquery_version': h.get('osquery_version'),
                                  'last_seen': h.get('seen_time'), 'uptime': h.get('uptime'), 'listening_ports': [], 'users': [], 'sudoers': [], 'packages': [], 'processes': []}
            page += 1
            await ctx.heartbeat()
        for fleet_id, host in hosts.items():
            detail = await client.get(f'{base}/api/v1/fleet/hosts/{fleet_id}')
            if detail.status_code != 200:
                warnings.append(f'host {fleet_id}: HTTP {detail.status_code}')
                continue
            data = detail.json().get('host', {})
            host['packages'] = [{'name': s.get('name'), 'version': s.get('version'), 'source': s.get('source')} for s in data.get('software') or []]
            host['users'] = [{'username': u.get('username'), 'uid': u.get('uid'), 'shell': u.get('shell'), 'groups': [u.get('groupname')] if u.get('groupname') else []}
                             for u in data.get('users') or []]
            await ctx.heartbeat()
        by_hostname = {h['hostname']: h for h in hosts.values() if h.get('hostname')}
        by_id = {h['fleet_id']: h for h in hosts.values()}
        for key, query_id in (config.get('query_reports') or {}).items():
            response = await client.get(f'{base}/api/v1/fleet/queries/{int(query_id)}/report')
            if response.status_code != 200:
                warnings.append(f'query report {key}: HTTP {response.status_code}')
                continue
            for row in response.json().get('results', []):
                host = by_id.get(row.get('host_id')) or by_hostname.get(row.get('host_name'))
                if host is None:
                    continue
                columns = row.get('columns') or {}
                if key == 'users' and isinstance(columns.get('groups'), str):
                    columns['groups'] = columns['groups'].split(',')
                host.setdefault(key, []).append(columns)
    return {'hosts': list(hosts.values()), 'warnings': warnings}


registry.register(OsqueryCollector())
