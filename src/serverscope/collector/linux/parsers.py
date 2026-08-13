"""Pure parsers for Linux command output. Kept side-effect free for unit testing."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from serverscope.core.models import FilesystemUsage, ProcessInfo

SECTION_RE = re.compile(r"^===(\w+)===$", re.MULTILINE)


def split_sections(output: str) -> dict[str, str]:
    """Split composite script output on ===name=== markers."""
    sections: dict[str, str] = {}
    parts = SECTION_RE.split(output)
    # parts = [prefix, name1, body1, name2, body2, ...]
    for i in range(1, len(parts) - 1, 2):
        sections[parts[i]] = parts[i + 1].strip()
    if len(parts) > 1 and len(parts) % 2 == 0:
        sections[parts[-1]] = ""
    return sections


def parse_os_release(text: str) -> tuple[str | None, str | None]:
    fields = dict(
        line.split("=", 1) for line in text.splitlines() if "=" in line
    )
    name = fields.get("NAME", "").strip('"') or None
    version = fields.get("VERSION_ID", "").strip('"') or None
    return name, version


def parse_uptime(text: str) -> tuple[float | None, datetime | None]:
    try:
        seconds = float(text.split()[0])
    except (ValueError, IndexError):
        return None, None
    return seconds, datetime.now(UTC) - timedelta(seconds=seconds)


def parse_loadavg(text: str) -> tuple[float, float, float] | None:
    parts = text.split()
    if len(parts) < 3:
        return None
    return float(parts[0]), float(parts[1]), float(parts[2])


def parse_proc_stat_cpu(line: str) -> list[int]:
    fields = line.split()
    if not fields or fields[0] != "cpu":
        return []
    return [int(v) for v in fields[1:]]


def cpu_pct_from_stat_pair(stat1: str, stat2: str) -> dict[str, float]:
    """Compute usage/idle/iowait/steal percentages from two /proc/stat cpu lines."""
    a, b = parse_proc_stat_cpu(stat1), parse_proc_stat_cpu(stat2)
    if len(a) < 8 or len(b) < 8:
        return {}
    delta = [y - x for x, y in zip(a, b)]
    total = sum(delta)
    if total <= 0:
        return {}
    idle = delta[3] + delta[4]  # idle + iowait
    return {
        "usage_pct": 100.0 * (total - idle) / total,
        "idle_pct": 100.0 * delta[3] / total,
        "iowait_pct": 100.0 * delta[4] / total,
        "steal_pct": 100.0 * delta[7] / total,
    }


def parse_free(text: str) -> dict[str, int]:
    """Parse `free -b` output."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if line.startswith("Mem:") and len(parts) >= 6:
            out["total"] = int(parts[1])
            out["used"] = int(parts[2])
            out["buff_cache"] = int(parts[5])
        elif line.startswith("Swap:") and len(parts) >= 3:
            out["swap_total"] = int(parts[1])
            out["swap_used"] = int(parts[2])
    return out


def parse_df(text: str) -> list[FilesystemUsage]:
    """Parse `df -PkT` output (sizes in KiB)."""
    result: list[FilesystemUsage] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            size_kb, used_kb = int(parts[2]), int(parts[3])
        except ValueError:
            continue
        result.append(
            FilesystemUsage(
                mount=parts[6], fstype=parts[1],
                size_bytes=size_kb * 1024, used_bytes=used_kb * 1024,
            )
        )
    return result


def _diskstats_totals(text: str) -> tuple[int, int, int, int]:
    """Sum (reads, writes, read_sectors, write_sectors) over physical devices."""
    reads = writes = rsec = wsec = 0
    for line in text.splitlines():
        f = line.split()
        if len(f) < 14:
            continue
        name = f[2]
        if re.search(r"\d+$", name) and not name.startswith(("nvme", "mmcblk")):
            continue  # skip partitions like sda1; keep nvme0n1/mmcblk0 whole disks
        reads += int(f[3])
        rsec += int(f[5])
        writes += int(f[7])
        wsec += int(f[9])
    return reads, writes, rsec, wsec


def disk_rates_from_pair(stats1: str, stats2: str, interval: float = 1.0) -> dict[str, float]:
    if not stats1.strip() or not stats2.strip():
        return {}  # no data must stay "unknown", not zero IO
    r1, w1, rs1, ws1 = _diskstats_totals(stats1)
    r2, w2, rs2, ws2 = _diskstats_totals(stats2)
    return {
        "iops_read": max(0.0, (r2 - r1) / interval),
        "iops_write": max(0.0, (w2 - w1) / interval),
        "read_mbps": max(0.0, (rs2 - rs1) * 512 / interval / 1_048_576),
        "write_mbps": max(0.0, (ws2 - ws1) * 512 / interval / 1_048_576),
    }


def _netdev_totals(text: str) -> tuple[int, int, int, int]:
    rx = tx = errs = drops = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        iface, data = line.split(":", 1)
        if iface.strip() == "lo":
            continue
        f = data.split()
        if len(f) >= 12:
            rx += int(f[0])
            errs += int(f[2]) + int(f[10])
            drops += int(f[3]) + int(f[11])
            tx += int(f[8])
    return rx, tx, errs, drops


def net_rates_from_pair(dev1: str, dev2: str, interval: float = 1.0) -> dict[str, float]:
    if not dev1.strip() or not dev2.strip():
        return {}
    rx1, tx1, e1, d1 = _netdev_totals(dev1)
    rx2, tx2, e2, d2 = _netdev_totals(dev2)
    return {
        "rx_bytes_per_sec": max(0.0, (rx2 - rx1) / interval),
        "tx_bytes_per_sec": max(0.0, (tx2 - tx1) / interval),
        "errors": float(e2),
        "dropped_packets": float(d2),
    }


def parse_ss_summary(text: str) -> int | None:
    m = re.search(r"estab (\d+)", text)
    return int(m.group(1)) if m else None


def parse_ss_listen(text: str) -> list[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        m = re.search(r"[\]:](\d+)\s", line + " ")
        parts = line.split()
        for p in parts:
            m = re.match(r".*[:\]](\d+)$", p)
            if m:
                ports.add(int(m.group(1)))
                break
    return sorted(ports)


def parse_ps(text: str, limit: int = 10) -> list[ProcessInfo]:
    procs: list[ProcessInfo] = []
    for line in text.splitlines()[1:]:
        f = line.split(None, 10)
        if len(f) < 11:
            continue
        try:
            procs.append(
                ProcessInfo(
                    pid=int(f[1]), user=f[0], cpu_pct=float(f[2]),
                    mem_pct=float(f[3]), name=f[10][:120],
                )
            )
        except ValueError:
            continue
    return procs[:limit]


def parse_last_login(text: str) -> datetime | None:
    """Best-effort parse of `last -F` for the most recent real user login."""
    for line in text.splitlines():
        if line.startswith(("reboot", "wtmp", "btmp")) or not line.strip():
            continue
        m = re.search(r"[A-Z][a-z]{2} ([A-Z][a-z]{2}) +(\d+) (\d+):(\d+):(\d+) (\d{4})", line)
        if m:
            months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            try:
                return datetime(
                    int(m.group(6)), months.index(m.group(1)) + 1, int(m.group(2)),
                    int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=UTC,
                )
            except ValueError:
                continue
    return None


def parse_int(text: str) -> int | None:
    try:
        return int(text.strip().splitlines()[0])
    except (ValueError, IndexError):
        return None
