# ServerScope

Enterprise infrastructure discovery and server utilization analysis framework.

Identifies **active**, **idle**, **underutilized**, **overloaded**, **hibernated**,
**forgotten**, **zombie**, **misconfigured** and **abnormal** servers — and produces
ranked **decommission candidates** with evidence-backed probabilities.

> Intended for use by infrastructure owners on systems they are authorized to manage.

## Supported platforms

| Platform | Method | Extra |
|---|---|---|
| Linux (Ubuntu, Debian, RHEL, Rocky, Alma, SUSE, Oracle) | SSH (asyncssh, one composite script) | `[linux]` |
| Windows Server | WinRM + PowerShell (CIM/WMI, event log) | `[windows]` |
| Active Directory | LDAP(S) computer-object enumeration | `[ad]` |
| VMware | vCenter API (pyvmomi) | `[vmware]` |
| Proxmox VE | REST API + RRD history | `[proxmox]` |
| AWS EC2 | boto3 + CloudWatch | `[aws]` |
| Azure VM | ARM + Azure Monitor | `[azure]` |
| GCP Compute Engine | compute + Cloud Monitoring | `[gcp]` |

Hyper-V hosts are covered through the Windows collector (WinRM against the host).

## Install

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -e ".[linux,ml,excel]"      # pick the extras you need
# everything: pip install -e ".[all]"
```

## Quick start

```bash
cp config/config.example.yaml config/config.yaml   # edit targets + credentials
serverscope -c config/config.yaml run              # collect + analyze + report + dashboard
serverscope -c config/config.yaml collect --target linux-prod
serverscope -c config/config.yaml analyze
serverscope -c config/config.yaml report --format html --format excel
serverscope -c config/config.yaml dashboard
```

Example output:

```
Server: APP-023  [linux]
  Classification:          decommission_candidate
  Health Score:            91/100
  Idle Probability:        94%
  Abandonment Probability: 89%
  Reasons:
    - no activity: cpu_average
    - no activity: disk_io
    - no user login for 300 days
  Recommendation: Likely abandoned server. Candidate for business validation
  and decommissioning.
```

## Architecture

```
src/serverscope/
  core/        models, config (+ env/file/Vault secrets), SQLite history,
               retry + token-bucket rate limiter, plugin registry
  collector/   linux/ windows/ ad/ vmware/ proxmox/ cloud/  + async orchestrator
  analyzer/    idle & abandonment scoring, anomaly detection, trends,
               local ML (isolation forest, DBSCAN, KMeans, seasonal decomposition)
  report/      json / csv / markdown / html / excel / pdf
  dashboard/   self-contained Chart.js dashboard
```

Design principles:

- **Weighted evidence, not guesses.** Idle/abandonment probability is the fraction of
  *available* signal weight indicating disuse; missing telemetry lowers confidence
  instead of inflating scores.
- **Modular + pluggable.** Collectors and reporters are entry-point plugins
  (`serverscope.collectors`, `serverscope.reporters`); third-party packages can add
  their own without touching this codebase.
- **Local-only analytics.** All statistics/ML run locally; sklearn is optional with
  pure-Python fallbacks. No external AI APIs.
- **Scale.** Async fan-out with bounded concurrency, connection rate limiting,
  per-host retries with jittered exponential backoff. One composite script per Linux
  host keeps it at ~2 round trips; 10 → 10,000 hosts is a config change.
- **History.** Every run appends to SQLite; trends, 95th percentiles, storage growth
  and baselines are computed over 1/7/30/90/365-day windows.

## Extending

```python
from serverscope.collector.base import BaseCollector
from serverscope.core.registry import collector_registry

@collector_registry.register("my_platform")
class MyCollector(BaseCollector):
    def hosts(self): ...
    async def collect_host(self, host): ...
```

Or ship it in your own package with an entry point in group `serverscope.collectors`.

## Development

```bash
pip install -e ".[dev]"
pytest
mypy src/serverscope
ruff check src tests
```
