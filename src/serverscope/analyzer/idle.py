"""Idle / hibernation / abandonment probability via weighted signal scoring.

Each signal contributes weight * confidence when it indicates disuse; the
probability is the fraction of *available* signal weight pointing to disuse.
Missing signals are excluded rather than assumed, so partial data never
inflates the probability.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from serverscope.core.config import IdleConfig
from serverscope.core.models import MetricSeries, ServerSnapshot


@dataclass(frozen=True)
class SignalVote:
    name: str
    weight: float
    idle: bool  # True = points toward disuse


def _days_since(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    ref = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - ref).total_seconds() / 86400.0


class IdleScorer:
    def __init__(self, config: IdleConfig) -> None:
        self.config = config

    def signals(
        self, snap: ServerSnapshot, cpu_history: MetricSeries | None = None
    ) -> list[SignalVote]:
        c = self.config
        votes: list[SignalVote] = []

        def vote(name: str, weight: float, value: bool | None) -> None:
            if value is not None:
                votes.append(SignalVote(name, weight, value))

        cpu_values = cpu_history.values() if cpu_history else []
        cpu_avg = (sum(cpu_values) / len(cpu_values)) if cpu_values else (
            snap.cpu.avg_pct if snap.cpu.avg_pct is not None else snap.cpu.usage_pct
        )
        vote("cpu_average", 3.0, None if cpu_avg is None else cpu_avg < c.cpu_avg_threshold_pct)

        iops = None
        if snap.disk.iops_read is not None or snap.disk.iops_write is not None:
            iops = (snap.disk.iops_read or 0.0) + (snap.disk.iops_write or 0.0)
        vote("disk_io", 2.5, None if iops is None else iops < c.io_iops_threshold)

        mbps = None
        if snap.disk.read_mbps is not None or snap.disk.write_mbps is not None:
            mbps = (snap.disk.read_mbps or 0.0) + (snap.disk.write_mbps or 0.0)
        vote("disk_throughput", 1.0, None if mbps is None else mbps < 0.5)

        login_days = _days_since(snap.activity.last_user_login)
        vote("user_logins", 3.0,
             None if login_days is None else login_days > c.login_lookback_days)
        vote("interactive_sessions", 1.5,
             None if snap.activity.interactive_sessions is None
             else snap.activity.interactive_sessions == 0)
        vote("ssh_sessions", 1.0,
             None if snap.activity.ssh_sessions is None else snap.activity.ssh_sessions == 0)
        vote("rdp_sessions", 1.0,
             None if snap.activity.rdp_sessions is None else snap.activity.rdp_sessions == 0)

        vote("cron_activity", 1.5, _negate(snap.activity.cron_active))
        vote("scheduled_tasks", 1.5, _negate(snap.activity.scheduled_tasks_active))
        vote("db_activity", 2.0, _negate(snap.activity.db_active))
        vote("app_logs", 1.5, _negate(snap.activity.app_log_activity))
        vote("web_requests", 2.0,
             None if snap.activity.web_requests_per_day is None
             else snap.activity.web_requests_per_day < 1.0)
        vote("auth_events", 1.5,
             None if snap.activity.auth_events_30d is None
             else snap.activity.auth_events_30d == 0)
        vote("files_modified", 1.5,
             None if snap.activity.files_modified_7d is None
             else snap.activity.files_modified_7d < 5)
        vote("registry_changes", 0.5,
             None if snap.activity.registry_changes_7d is None
             else snap.activity.registry_changes_7d == 0)
        vote("ad_logons", 2.0,
             None if snap.activity.ad_logons_30d is None else snap.activity.ad_logons_30d == 0)
        vote("dns_queries", 1.0,
             None if snap.activity.dns_queries_per_day is None
             else snap.activity.dns_queries_per_day < 1.0)
        vote("dhcp_lease", 0.5, _negate(snap.activity.dhcp_lease_active))
        vote("monitoring", 1.0, _negate(snap.activity.monitoring_active))
        backup_days = _days_since(snap.activity.backup_last)
        vote("backups", 1.5, None if backup_days is None else backup_days > 30)
        vote("security_events", 1.0,
             None if snap.activity.security_events_30d is None
             else snap.activity.security_events_30d == 0)
        vote("cert_renewal", 0.5, _negate(snap.activity.cert_renewed_recently))
        vote("heartbeat", 1.0, _negate(snap.activity.heartbeat_ok))
        vote("vm_tools", 1.0, _negate(snap.activity.vm_tools_active))
        vote("containers", 1.0,
             None if snap.activity.containers_running is None
             else snap.activity.containers_running == 0)
        vote("k8s_pods", 1.0,
             None if snap.activity.k8s_pods_running is None
             else snap.activity.k8s_pods_running == 0)

        est = snap.network.connections_established
        vote("network_connections", 2.0, None if est is None else est <= 1)

        net_bps = None
        if (snap.network.rx_bytes_per_sec is not None
                or snap.network.tx_bytes_per_sec is not None):
            net_bps = ((snap.network.rx_bytes_per_sec or 0.0)
                       + (snap.network.tx_bytes_per_sec or 0.0))
        vote("network_throughput", 2.0, None if net_bps is None else net_bps < 1024)
        return votes

    def idle_probability(
        self, snap: ServerSnapshot, cpu_history: MetricSeries | None = None
    ) -> tuple[float, list[str]]:
        votes = self.signals(snap, cpu_history)
        available = sum(v.weight for v in votes)
        if available == 0:
            return 0.0, ["insufficient signals"]
        idle_weight = sum(v.weight for v in votes if v.idle)
        # Confidence scales with breadth of evidence: few signals cap the score.
        confidence = min(1.0, len(votes) / 8.0)
        probability = 100.0 * (idle_weight / available) * confidence
        reasons = [f"no activity: {v.name}" for v in votes if v.idle]
        return round(probability, 1), reasons

    def hibernation_probability(
        self, snap: ServerSnapshot, cpu_history: MetricSeries | None = None
    ) -> float:
        """Stricter variant: near-zero CPU + long uptime + zero activity."""
        prob, _ = self.idle_probability(snap, cpu_history)
        cpu = snap.cpu.avg_pct if snap.cpu.avg_pct is not None else snap.cpu.usage_pct
        if cpu is not None and cpu >= self.config.hibernated_cpu_threshold_pct:
            return round(prob * 0.4, 1)
        uptime_days = (snap.identity.uptime_seconds or 0) / 86400.0
        if uptime_days > 180:
            prob = min(100.0, prob * 1.1)
        return round(prob, 1)

    def abandonment_probability(
        self, snap: ServerSnapshot, cpu_history: MetricSeries | None = None
    ) -> tuple[float, list[str]]:
        """Abandonment = sustained idleness + stale ownership signals."""
        prob, reasons = self.idle_probability(snap, cpu_history)
        boosters = 0.0
        login_days = _days_since(snap.activity.last_user_login)
        if login_days is not None and login_days > 180:
            boosters += 10
            reasons.append(f"no user login for {int(login_days)} days")
        if snap.ad:
            ad_days = _days_since(snap.ad.last_logon_timestamp)
            if ad_days is not None and ad_days > 90:
                boosters += 10
                reasons.append(f"AD lastLogonTimestamp {int(ad_days)} days old")
            if snap.ad.password_age_days is not None and snap.ad.password_age_days > 90:
                boosters += 5
                reasons.append(f"computer password age {snap.ad.password_age_days} days")
        backup_days = _days_since(snap.activity.backup_last)
        if backup_days is not None and backup_days > 90:
            boosters += 5
            reasons.append(f"last backup {int(backup_days)} days ago")
        return round(min(100.0, prob * 0.85 + boosters), 1), reasons


def _negate(value: bool | None) -> bool | None:
    return None if value is None else not value
