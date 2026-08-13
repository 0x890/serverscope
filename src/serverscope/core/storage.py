"""SQLite persistence for snapshots and historical metric series."""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from serverscope.core.models import MetricPoint, MetricSeries, ServerSnapshot

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_host ON snapshots(hostname, collected_at);
CREATE TABLE IF NOT EXISTS metrics (
    hostname TEXT NOT NULL,
    metric TEXT NOT NULL,
    ts TEXT NOT NULL,
    value REAL NOT NULL,
    PRIMARY KEY (hostname, metric, ts)
);
"""

_TRACKED: dict[str, str] = {
    "cpu_pct": "cpu.usage_pct",
    "mem_pct": "memory.used_pct",
    "iops_read": "disk.iops_read",
    "iops_write": "disk.iops_write",
    "net_rx": "network.rx_bytes_per_sec",
    "net_tx": "network.tx_bytes_per_sec",
}


class MetricStore:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(Path(path).expanduser()))
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def save_snapshot(self, snapshot: ServerSnapshot) -> None:
        host = snapshot.identity.hostname
        ts = snapshot.collected_at.isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT INTO snapshots (hostname, platform, collected_at, payload) VALUES (?,?,?,?)",
                (host, snapshot.platform.value, ts, snapshot.model_dump_json()),
            )
            for metric, value in self._extract(snapshot).items():
                self._conn.execute(
                    "INSERT OR REPLACE INTO metrics (hostname, metric, ts, value) VALUES (?,?,?,?)",
                    (host, metric, ts, value),
                )

    def record_metric(self, hostname: str, metric: str, ts: datetime, value: float) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO metrics (hostname, metric, ts, value) VALUES (?,?,?,?)",
                (hostname, metric, ts.isoformat(), value),
            )

    def latest_snapshots(self) -> list[ServerSnapshot]:
        rows = self._conn.execute(
            """SELECT payload FROM snapshots s
               WHERE collected_at = (SELECT MAX(collected_at) FROM snapshots
                                     WHERE hostname = s.hostname)"""
        ).fetchall()
        return [ServerSnapshot.model_validate(json.loads(r[0])) for r in rows]

    def history(self, hostname: str, metric: str, days: int) -> MetricSeries:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        rows = self._conn.execute(
            "SELECT ts, value FROM metrics WHERE hostname=? AND metric=? AND ts>=? ORDER BY ts",
            (hostname, metric, since),
        ).fetchall()
        return MetricSeries(
            name=metric,
            points=[MetricPoint(ts=datetime.fromisoformat(ts), value=v) for ts, v in rows],
        )

    def hostnames(self) -> list[str]:
        return [r[0] for r in self._conn.execute("SELECT DISTINCT hostname FROM snapshots")]

    @staticmethod
    def _extract(snapshot: ServerSnapshot) -> dict[str, float]:
        out: dict[str, float] = {}
        if snapshot.cpu.usage_pct is not None:
            out["cpu_pct"] = snapshot.cpu.usage_pct
        mem_pct = snapshot.memory.used_pct
        if mem_pct is not None:
            out["mem_pct"] = mem_pct
        if snapshot.disk.iops_read is not None:
            out["iops_read"] = snapshot.disk.iops_read
        if snapshot.disk.iops_write is not None:
            out["iops_write"] = snapshot.disk.iops_write
        if snapshot.network.rx_bytes_per_sec is not None:
            out["net_rx"] = snapshot.network.rx_bytes_per_sec
        if snapshot.network.tx_bytes_per_sec is not None:
            out["net_tx"] = snapshot.network.tx_bytes_per_sec
        for fs in snapshot.disk.filesystems:
            out[f"fs_used:{fs.mount}"] = float(fs.used_bytes)
        return out
