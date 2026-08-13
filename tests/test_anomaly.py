from __future__ import annotations

from datetime import UTC, datetime, timedelta

from serverscope.analyzer.anomaly import AnomalyDetector
from serverscope.core.models import (
    CpuMetrics,
    DiskMetrics,
    FilesystemUsage,
    MemoryMetrics,
    MetricPoint,
    MetricSeries,
    OsState,
)
from tests.conftest import make_snapshot


def kinds(anomalies) -> set[str]:  # noqa: ANN001
    return {a.kind for a in anomalies}


def test_cpu_steal_detected() -> None:
    snap = make_snapshot(cpu=CpuMetrics(usage_pct=50.0, steal_pct=25.0, cores=4))
    assert "cpu_steal" in kinds(AnomalyDetector().detect(snap))


def test_filesystem_full() -> None:
    snap = make_snapshot(disk=DiskMetrics(filesystems=[
        FilesystemUsage(mount="/data", size_bytes=100, used_bytes=95),
    ]))
    assert "filesystem_full" in kinds(AnomalyDetector().detect(snap))


def test_oom_events() -> None:
    snap = make_snapshot(memory=MemoryMetrics(total_bytes=100, used_bytes=50, oom_events=3))
    assert "oom_events" in kinds(AnomalyDetector().detect(snap))


def test_memory_leak_trend() -> None:
    now = datetime.now(UTC)
    points = [MetricPoint(ts=now - timedelta(hours=48 - i), value=40.0 + i * 0.5)
              for i in range(48)]
    history = {"mem_pct": MetricSeries(name="mem_pct", points=points)}
    snap = make_snapshot()
    assert "memory_leak_suspect" in kinds(AnomalyDetector().detect(snap, history))


def test_time_drift() -> None:
    snap = make_snapshot(os_state=OsState(time_synced=False))
    assert "time_drift" in kinds(AnomalyDetector().detect(snap))


def test_healthy_snapshot_no_critical(active_snapshot) -> None:  # noqa: ANN001
    from serverscope.core.models import Severity

    anomalies = AnomalyDetector().detect(active_snapshot)
    assert not [a for a in anomalies if a.severity == Severity.CRITICAL]
