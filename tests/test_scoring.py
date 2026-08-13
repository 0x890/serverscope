from __future__ import annotations

from serverscope.analyzer.anomaly import AnomalyDetector
from serverscope.analyzer.scoring import ScoringEngine
from serverscope.core.config import ScoringConfig
from serverscope.core.models import (
    Classification,
    CpuMetrics,
    MemoryMetrics,
    ServerSnapshot,
)
from tests.conftest import make_snapshot


def engine() -> ScoringEngine:
    return ScoringEngine(ScoringConfig())


def analyze(snap: ServerSnapshot):  # noqa: ANN201
    anomalies = AnomalyDetector().detect(snap)
    return engine().score(snap, anomalies)


def test_healthy_server_is_active(active_snapshot: ServerSnapshot) -> None:
    result = analyze(active_snapshot)
    assert result.classification == Classification.ACTIVE
    assert result.scores.health > 70


def test_abandoned_server_flagged(abandoned_snapshot: ServerSnapshot) -> None:
    result = analyze(abandoned_snapshot)
    assert result.classification in (
        Classification.DECOMMISSION_CANDIDATE,
        Classification.FORGOTTEN,
        Classification.HIBERNATED,
    )
    assert result.scores.abandonment_probability > 60
    assert "decommission" in result.recommendation.lower() or result.reasons


def test_overloaded_server() -> None:
    snap = make_snapshot(
        cpu=CpuMetrics(usage_pct=97.0, p95_pct=96.0, cores=4, load_15=10.0),
        memory=MemoryMetrics(total_bytes=16 * 1024**3, used_bytes=15 * 1024**3),
    )
    result = analyze(snap)
    assert result.classification == Classification.OVERLOADED
    assert result.scores.performance < 80


def test_scores_bounded(abandoned_snapshot: ServerSnapshot,
                        active_snapshot: ServerSnapshot) -> None:
    for snap in (abandoned_snapshot, active_snapshot):
        s = analyze(snap).scores
        for value in (s.health, s.risk, s.performance, s.security,
                      s.availability, s.maintenance,
                      s.idle_probability, s.abandonment_probability):
            assert 0.0 <= value <= 100.0


def test_weights_must_sum_to_one() -> None:
    import pytest

    with pytest.raises(ValueError):
        ScoringConfig(weights={"performance": 0.9, "security": 0.9,
                               "availability": 0.1, "maintenance": 0.1})
