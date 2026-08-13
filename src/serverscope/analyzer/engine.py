"""Analysis pipeline: per-host scoring + fleet-level multivariate outlier detection."""
from __future__ import annotations

import logging

from serverscope.analyzer import ml
from serverscope.analyzer.anomaly import AnomalyDetector
from serverscope.analyzer.scoring import ScoringEngine
from serverscope.core.config import AppConfig
from serverscope.core.models import (
    AnalysisResult,
    Anomaly,
    MetricSeries,
    ServerSnapshot,
    Severity,
)
from serverscope.core.storage import MetricStore

log = logging.getLogger(__name__)

_HISTORY_METRICS = ("cpu_pct", "mem_pct", "iops_read", "iops_write", "net_rx", "net_tx")


class AnalysisEngine:
    def __init__(self, config: AppConfig, store: MetricStore) -> None:
        self.config = config
        self.store = store
        self.detector = AnomalyDetector()
        self.scorer = ScoringEngine(config.scoring)

    def analyze(self, snapshots: list[ServerSnapshot]) -> list[AnalysisResult]:
        results: list[AnalysisResult] = []
        for snap in snapshots:
            history = self._history(snap.identity.hostname)
            anomalies = self.detector.detect(snap, history)
            results.append(self.scorer.score(snap, anomalies, history))
        self._fleet_outliers(snapshots, results)
        return sorted(results, key=lambda r: r.scores.abandonment_probability, reverse=True)

    def _history(self, hostname: str) -> dict[str, MetricSeries]:
        days = max(self.config.history.windows_days)
        return {m: self.store.history(hostname, m, days) for m in _HISTORY_METRICS}

    def _fleet_outliers(
        self, snapshots: list[ServerSnapshot], results: list[AnalysisResult]
    ) -> None:
        """Isolation-forest across the fleet flags hosts behaving unlike peers."""
        matrix: list[list[float]] = []
        for s in snapshots:
            matrix.append([
                s.cpu.usage_pct or 0.0,
                s.memory.used_pct or 0.0,
                (s.disk.iops_read or 0.0) + (s.disk.iops_write or 0.0),
                float(s.network.connections_established or 0),
                float(len(s.network.open_ports)),
            ])
        scores = ml.isolation_forest_scores(matrix)
        if not scores:
            return
        for result, score in zip(results, scores):
            if score > 0.85:
                result.anomalies.append(Anomaly(
                    kind="fleet_outlier", severity=Severity.WARNING,
                    description="behaviour deviates strongly from fleet peers",
                    evidence={"outlier_score": round(score, 3)},
                ))
