"""Weighted scoring engine: health, risk, sub-scores, classification, recommendation."""
from __future__ import annotations

from serverscope.analyzer.idle import IdleScorer
from serverscope.core.config import ScoringConfig
from serverscope.core.models import (
    AnalysisResult,
    Anomaly,
    Classification,
    MetricSeries,
    Scores,
    ServerSnapshot,
    Severity,
)


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


class ScoringEngine:
    def __init__(self, config: ScoringConfig) -> None:
        self.config = config
        self.idle_scorer = IdleScorer(config.idle)

    def score(
        self,
        snap: ServerSnapshot,
        anomalies: list[Anomaly],
        history: dict[str, MetricSeries] | None = None,
    ) -> AnalysisResult:
        history = history or {}
        cpu_hist = history.get("cpu_pct")

        performance = self._performance(snap)
        security = self._security(snap, anomalies)
        availability = self._availability(snap, anomalies)
        maintenance = self._maintenance(snap)

        w = self.config.weights
        health = _clamp(
            performance * w.get("performance", 0.3)
            + security * w.get("security", 0.25)
            + availability * w.get("availability", 0.25)
            + maintenance * w.get("maintenance", 0.2)
        )

        idle_prob, idle_reasons = self.idle_scorer.idle_probability(snap, cpu_hist)
        abandon_prob, abandon_reasons = self.idle_scorer.abandonment_probability(snap, cpu_hist)

        criticality = self._criticality(snap)
        risk = _clamp(
            (100 - health) * 0.5
            + criticality * 0.3
            + 10 * sum(1 for a in anomalies if a.severity == Severity.CRITICAL)
        )

        scores = Scores(
            health=round(health, 1),
            risk=round(risk, 1),
            criticality=round(criticality, 1),
            business_impact=round(criticality, 1),
            performance=round(performance, 1),
            security=round(security, 1),
            availability=round(availability, 1),
            maintenance=round(maintenance, 1),
            idle_probability=idle_prob,
            abandonment_probability=abandon_prob,
        )

        classification = self._classify(snap, scores, anomalies)
        reasons = list(dict.fromkeys(abandon_reasons if abandon_prob >= idle_prob else idle_reasons))
        recommendation = self._recommend(classification, scores)

        return AnalysisResult(
            hostname=snap.identity.hostname,
            platform=snap.platform,
            scores=scores,
            classification=classification,
            anomalies=anomalies,
            reasons=reasons[:12],
            recommendation=recommendation,
        )

    def _performance(self, s: ServerSnapshot) -> float:
        score = 100.0
        t = self.config.thresholds
        cpu = s.cpu.p95_pct if s.cpu.p95_pct is not None else s.cpu.usage_pct
        if cpu is not None and cpu > t.overloaded_cpu_pct:
            score -= min(35, (cpu - t.overloaded_cpu_pct) * 2)
        mem = s.memory.used_pct
        if mem is not None and mem > t.overloaded_mem_pct:
            score -= min(25, (mem - t.overloaded_mem_pct) * 2.5)
        if s.cpu.iowait_pct is not None and s.cpu.iowait_pct > 10:
            score -= min(20, s.cpu.iowait_pct)
        if s.cpu.steal_pct is not None and s.cpu.steal_pct > 5:
            score -= min(15, s.cpu.steal_pct)
        if s.cpu.load_15 is not None and s.cpu.cores:
            ratio = s.cpu.load_15 / s.cpu.cores
            if ratio > 1.5:
                score -= min(20, (ratio - 1.5) * 10)
        return _clamp(score)

    def _security(self, s: ServerSnapshot, anomalies: list[Anomaly]) -> float:
        score = 100.0
        if s.network.firewall_active is False:
            score -= 20
        if s.os_state.selinux and s.os_state.selinux.lower() == "disabled":
            score -= 10
        if (s.os_state.updates_pending or 0) > 20:
            score -= min(25, (s.os_state.updates_pending or 0) / 4)
        if s.os_state.antivirus is None and s.platform.value == "windows":
            score -= 15
        if s.os_state.bitlocker is False:
            score -= 5
        if (s.activity.auth_events_30d or 0) > 200:
            score -= 20
        score -= 10 * sum(
            1 for a in anomalies
            if a.severity == Severity.CRITICAL and a.kind.startswith(("ad_", "auth"))
        )
        return _clamp(score)

    def _availability(self, s: ServerSnapshot, anomalies: list[Anomaly]) -> float:
        score = 100.0
        for a in anomalies:
            if a.kind in ("filesystem_full", "oom_events", "failing_disk", "load_saturation"):
                score -= 20
            elif a.severity == Severity.CRITICAL:
                score -= 10
        if (s.processes.services_failed or 0) > 0:
            score -= min(15, 5 * (s.processes.services_failed or 0))
        if s.activity.heartbeat_ok is False:
            score -= 30
        return _clamp(score)

    def _maintenance(self, s: ServerSnapshot) -> float:
        score = 100.0
        if s.os_state.reboot_required:
            score -= 15
        uptime_days = (s.identity.uptime_seconds or 0) / 86400
        if uptime_days > 365:
            score -= 20
        elif uptime_days > 180:
            score -= 10
        if (s.os_state.updates_pending or 0) > 0:
            score -= min(20, (s.os_state.updates_pending or 0) / 5)
        backup = s.activity.backup_last
        if backup is None and s.activity.monitoring_active is False:
            score -= 10
        if s.os_state.time_synced is False:
            score -= 10
        return _clamp(score)

    def _criticality(self, s: ServerSnapshot) -> float:
        score = 30.0
        env = (s.identity.environment or "").lower()
        if env in ("production", "prod"):
            score += 40
        elif env in ("staging", "preprod"):
            score += 20
        critical_ports = {443, 1433, 1521, 3306, 5432, 389, 636, 88, 53}
        if critical_ports & set(s.network.open_ports):
            score += 20
        if (s.network.connections_established or 0) > 100:
            score += 10
        return _clamp(score)

    def _classify(
        self, s: ServerSnapshot, scores: Scores, anomalies: list[Anomaly]
    ) -> Classification:
        t = self.config.thresholds
        power = s.identity.tags.get("power") or s.identity.tags.get("status")
        heartbeat_dead = s.activity.heartbeat_ok is False or power in (
            "poweredOff", "stopped",
        )
        if heartbeat_dead:
            return (Classification.ZOMBIE if scores.abandonment_probability > 50
                    else Classification.HIBERNATED)
        if scores.abandonment_probability >= 85:
            return Classification.DECOMMISSION_CANDIDATE
        if scores.abandonment_probability >= 70:
            return Classification.FORGOTTEN
        hib = self.idle_scorer.hibernation_probability(s)
        if hib >= 70:
            return Classification.HIBERNATED
        cpu = s.cpu.p95_pct if s.cpu.p95_pct is not None else s.cpu.usage_pct
        mem = s.memory.used_pct
        if (cpu is not None and cpu > t.overloaded_cpu_pct) or (
            mem is not None and mem > t.overloaded_mem_pct
        ):
            return Classification.OVERLOADED
        if any(a.severity == Severity.CRITICAL for a in anomalies):
            return Classification.ABNORMAL
        if any(a.kind in ("time_drift", "dns_unregistered", "patching_neglected")
               for a in anomalies):
            return Classification.MISCONFIGURED
        if scores.idle_probability >= 60:
            return Classification.IDLE
        if cpu is not None and cpu < 15 and scores.idle_probability >= 30:
            return Classification.UNDERUTILIZED
        return Classification.ACTIVE

    @staticmethod
    def _recommend(classification: Classification, scores: Scores) -> str:
        match classification:
            case Classification.DECOMMISSION_CANDIDATE:
                return ("Likely abandoned server. Candidate for business validation "
                        "and decommissioning.")
            case Classification.ZOMBIE:
                return ("Powered-off/dead guest still consuming inventory. Validate and "
                        "remove from hypervisor, AD, DNS, CMDB and backups.")
            case Classification.FORGOTTEN:
                return ("No meaningful activity and stale ownership signals. Identify the "
                        "owner; schedule decommission review.")
            case Classification.HIBERNATED:
                return ("Server appears dormant. Confirm with the business, then snapshot "
                        "and power off before reclaiming resources.")
            case Classification.IDLE:
                return "Very low utilisation. Consider consolidation or right-sizing."
            case Classification.UNDERUTILIZED:
                return "Consistently under-utilised. Right-size (fewer vCPU/RAM) to cut cost."
            case Classification.OVERLOADED:
                return "Resource saturation. Scale up/out or rebalance workloads."
            case Classification.ABNORMAL:
                return "Critical anomalies detected. Investigate before they impact service."
            case Classification.MISCONFIGURED:
                return "Configuration hygiene issues detected. Remediate per anomaly list."
            case _:
                return ("Healthy and in use. No action required."
                        if scores.health >= 80 else
                        "In use, but health degraded. Review anomalies and maintenance items.")
