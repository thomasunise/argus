# Threat intel enrichment (CISA KEV and EPSS)

Every finding that names a CVE is checked against the CISA Known Exploited Vulnerabilities (KEV)
catalog and scored with FIRST EPSS, automatically.

## What happens

1. A scanner, collector or ingest source creates a finding with CVE ids (`finding.created`).
2. A debounced `intel.enrich` job picks up every not-yet-checked CVE finding of that tenant (scanners
   create hundreds at once; one job handles them all).
3. For each finding:
   - `kev` is set when any of its CVEs is in KEV, and the finding gets the `kev` tag;
   - `epss` is set to the highest EPSS score among its CVEs;
   - the evidence gets an `intel` block: which CVEs are listed, KEV date added and due date, known
     ransomware use, per-CVE EPSS score and percentile, and when it was checked;
   - a KEV-listed finding is raised to at least `INTEL_KEV_MIN_SEVERITY` (default `high`). The original
     severity is kept in `evidence.intel.severity_raised_from`. Severity is never lowered.
   - optionally, findings with EPSS at or above `INTEL_EPSS_ESCALATE_THRESHOLD` are raised to `high`.
4. Once a day the KEV catalog is refreshed and every open CVE finding is re-checked, because CISA adds
   to KEV every week.

Each enrichment batch that changes something writes one `intel.enriched` audit entry.

## Caching and offline use

Feeds are cached on disk in `INTEL_CACHE_DIR` (default `./data/intel`):

| File | Source | Refresh |
|---|---|---|
| `kev.json` | CISA KEV JSON feed | every `INTEL_KEV_REFRESH_HOURS` (12) |
| `epss.json` | FIRST EPSS API, per CVE, batched 100 at a time | entries older than `INTEL_EPSS_TTL_HOURS` (24) |
| `epss_scores-current.csv.gz` | optional bulk file you download | when you replace it |

A failed or malformed download never replaces a good cache. When the network is down, a stale
cached score is used rather than none.

For air-gapped installs set `INTEL_OFFLINE=true` and copy two files into the cache directory:

- `kev.json` from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- `epss_scores-current.csv.gz` from https://epss.cyentia.com/epss_scores-current.csv.gz

Nothing in the intel package touches the network in offline mode. The agents' `kev_check` tool also
reads the cached catalog first.

## API

See "Threat intel" in `docs/API.md`: `GET /intel/status`, `POST /intel/refresh`, `POST /intel/enrich`
(backfill), `GET /intel/cve/{id}`.

## Settings

`INTEL_ENRICHMENT_ENABLED`, `INTEL_OFFLINE`, `INTEL_CACHE_DIR`, `INTEL_KEV_REFRESH_HOURS`,
`INTEL_EPSS_TTL_HOURS`, `INTEL_KEV_MIN_SEVERITY`, `INTEL_EPSS_ESCALATE_THRESHOLD` (see `.env.example`).
