"""Builds a self-contained interactive HTML dashboard (Chart.js)."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader

from serverscope.core.storage import MetricStore
from serverscope.report.base import ReportContext


class DashboardBuilder:
    def __init__(self, store: MetricStore) -> None:
        self.store = store

    def build(self, context: ReportContext, output: str | Path) -> Path:
        payload = self._payload(context)
        env = Environment(loader=PackageLoader("serverscope.dashboard", "templates"))
        html = env.get_template("dashboard.html.j2").render(
            generated_at=context.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
            servers=context.results,
            payload=json.dumps(payload),
        )
        path = Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return path

    def _payload(self, context: ReportContext) -> dict[str, object]:
        servers = []
        disks: list[dict[str, object]] = []
        for r in context.results:
            snap = context.snapshots.get(r.hostname)
            cpu = snap.cpu.usage_pct if snap else None
            mem = snap.memory.used_pct if snap else None
            servers.append({
                "host": r.hostname,
                "classification": r.classification.value,
                "health": r.scores.health,
                "risk": r.scores.risk,
                "idle": r.scores.idle_probability,
                "abandon": r.scores.abandonment_probability,
                "cpu": round(cpu, 1) if cpu is not None else None,
                "mem": round(mem, 1) if mem is not None else None,
                "recommendation": r.recommendation,
            })
            if snap:
                for fs in snap.disk.filesystems:
                    disks.append({
                        "label": f"{r.hostname}:{fs.mount}",
                        "pct": round(fs.used_pct, 1),
                    })
        disks.sort(key=lambda d: float(d["pct"]), reverse=True)  # type: ignore[arg-type]

        buckets = [0] * 10
        for s in servers:
            buckets[min(9, int(float(s["health"]) // 10))] += 1  # type: ignore[arg-type]

        return {
            "servers": servers,
            "classifications": dict(context.classification_counts),
            "health_buckets": {
                "labels": [f"{i * 10}-{i * 10 + 9}" for i in range(10)],
                "counts": buckets,
            },
            "cpu_trend": self._fleet_cpu_trend(),
            "disks": disks[:15],
        }

    def _fleet_cpu_trend(self) -> dict[str, list[str] | list[float]]:
        """Daily fleet-average CPU over the last 30 days."""
        daily: dict[str, list[float]] = {}
        for host in self.store.hostnames():
            for p in self.store.history(host, "cpu_pct", 30).points:
                daily.setdefault(p.ts.strftime("%Y-%m-%d"), []).append(p.value)
        labels = sorted(daily)
        if not labels:
            today = datetime.now(UTC).strftime("%Y-%m-%d")
            return {"labels": [today], "values": [0.0]}
        return {
            "labels": labels,
            "values": [round(sum(daily[d]) / len(daily[d]), 2) for d in labels],
        }
