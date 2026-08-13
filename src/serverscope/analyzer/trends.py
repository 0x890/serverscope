"""Historical trend analysis: growth rates, forecasts, capacity planning."""
from __future__ import annotations

from dataclasses import dataclass

from serverscope.analyzer import ml
from serverscope.core.models import MetricSeries
from serverscope.core.storage import MetricStore


@dataclass
class StorageForecast:
    mount: str
    used_pct: float
    growth_gb_per_day: float
    days_until_full: int | None


@dataclass
class TrendSummary:
    hostname: str
    cpu_avg: dict[int, float]        # window days -> average
    cpu_p95: dict[int, float]
    cpu_trend_per_day: float
    mem_trend_per_day: float
    storage: list[StorageForecast]


class TrendAnalyzer:
    def __init__(self, store: MetricStore, windows_days: list[int]) -> None:
        self.store = store
        self.windows = windows_days

    def summarize(self, hostname: str) -> TrendSummary:
        cpu_avg: dict[int, float] = {}
        cpu_p95: dict[int, float] = {}
        for days in self.windows:
            series = self.store.history(hostname, "cpu_pct", days)
            values = series.values()
            if values:
                cpu_avg[days] = round(sum(values) / len(values), 2)
                p95 = ml.percentile(values, 95)
                if p95 is not None:
                    cpu_p95[days] = round(p95, 2)
        cpu_series = self.store.history(hostname, "cpu_pct", max(self.windows))
        mem_series = self.store.history(hostname, "mem_pct", max(self.windows))
        return TrendSummary(
            hostname=hostname,
            cpu_avg=cpu_avg,
            cpu_p95=cpu_p95,
            cpu_trend_per_day=round(_daily_slope(cpu_series), 4),
            mem_trend_per_day=round(_daily_slope(mem_series), 4),
            storage=self.storage_forecasts(hostname),
        )

    def storage_forecasts(self, hostname: str) -> list[StorageForecast]:
        out: list[StorageForecast] = []
        # filesystem series are stored as fs_used:<mount> in bytes
        for metric in self._fs_metrics(hostname):
            series = self.store.history(hostname, metric, 90)
            if len(series.points) < 2:
                continue
            values = series.values()
            span_days = max(
                1e-6,
                (series.points[-1].ts - series.points[0].ts).total_seconds() / 86400,
            )
            growth_bytes_per_day = (values[-1] - values[0]) / span_days
            gb_per_day = growth_bytes_per_day / 1024**3
            out.append(StorageForecast(
                mount=metric.split(":", 1)[1],
                used_pct=0.0,
                growth_gb_per_day=round(gb_per_day, 3),
                days_until_full=None,
            ))
        return out

    def _fs_metrics(self, hostname: str) -> list[str]:
        rows = self.store._conn.execute(  # noqa: SLF001 - internal helper
            "SELECT DISTINCT metric FROM metrics WHERE hostname=? AND metric LIKE 'fs_used:%'",
            (hostname,),
        ).fetchall()
        return [r[0] for r in rows]


def _daily_slope(series: MetricSeries) -> float:
    values = series.values()
    if len(values) < 2:
        return 0.0
    span_days = max(
        1e-6, (series.points[-1].ts - series.points[0].ts).total_seconds() / 86400
    )
    return ml.linear_trend(values) * (len(values) - 1) / span_days
