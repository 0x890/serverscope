from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    DiskMetrics,
    FilesystemUsage,
    HostIdentity,
    MemoryMetrics,
    NetworkMetrics,
    Platform,
    ServerSnapshot,
)

NOW = datetime.now(UTC)


def make_snapshot(**overrides: object) -> ServerSnapshot:
    base = ServerSnapshot(
        collected_at=NOW,
        platform=Platform.LINUX,
        identity=HostIdentity(hostname="test01", uptime_seconds=86400 * 10),
        cpu=CpuMetrics(usage_pct=25.0, cores=4, load_1=0.5, load_5=0.5, load_15=0.5),
        memory=MemoryMetrics(total_bytes=16 * 1024**3, used_bytes=8 * 1024**3),
        disk=DiskMetrics(
            filesystems=[FilesystemUsage(mount="/", fstype="ext4",
                                         size_bytes=100 * 1024**3,
                                         used_bytes=40 * 1024**3)],
            iops_read=50.0, iops_write=30.0,
        ),
        network=NetworkMetrics(connections_established=42, open_ports=[22, 443]),
        activity=ActivitySignals(
            last_user_login=NOW - timedelta(days=2),
            interactive_sessions=1,
            cron_active=True,
            monitoring_active=True,
        ),
    )
    return base.model_copy(update=overrides)  # type: ignore[arg-type]


def make_abandoned_snapshot() -> ServerSnapshot:
    return make_snapshot(
        identity=HostIdentity(hostname="ghost01", uptime_seconds=86400 * 400),
        cpu=CpuMetrics(usage_pct=0.4, avg_pct=0.5, cores=2),
        disk=DiskMetrics(iops_read=0.1, iops_write=0.0, read_mbps=0.0, write_mbps=0.0),
        network=NetworkMetrics(connections_established=0),
        activity=ActivitySignals(
            last_user_login=NOW - timedelta(days=300),
            interactive_sessions=0,
            ssh_sessions=0,
            cron_active=False,
            scheduled_tasks_active=False,
            db_active=False,
            app_log_activity=False,
            web_requests_per_day=0.0,
            auth_events_30d=0,
            files_modified_7d=0,
            ad_logons_30d=0,
            monitoring_active=False,
            backup_last=NOW - timedelta(days=200),
            security_events_30d=0,
            containers_running=0,
        ),
    )


@pytest.fixture
def active_snapshot() -> ServerSnapshot:
    return make_snapshot()


@pytest.fixture
def abandoned_snapshot() -> ServerSnapshot:
    return make_abandoned_snapshot()
