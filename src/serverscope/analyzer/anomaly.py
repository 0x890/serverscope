"""Rule + statistics based anomaly detection per server."""
from __future__ import annotations

from serverscope.analyzer import ml
from serverscope.core.models import Anomaly, MetricSeries, ServerSnapshot, Severity


class AnomalyDetector:
    def detect(
        self,
        snap: ServerSnapshot,
        history: dict[str, MetricSeries] | None = None,
    ) -> list[Anomaly]:
        history = history or {}
        anomalies: list[Anomaly] = []
        anomalies += self._cpu(snap)
        anomalies += self._memory(snap, history.get("mem_pct"))
        anomalies += self._disk(snap)
        anomalies += self._network(snap)
        anomalies += self._processes(snap)
        anomalies += self._os(snap)
        anomalies += self._ad(snap)
        anomalies += self._statistical(snap, history)
        return anomalies

    def _cpu(self, s: ServerSnapshot) -> list[Anomaly]:
        out: list[Anomaly] = []
        if s.cpu.steal_pct is not None and s.cpu.steal_pct > 10:
            out.append(Anomaly(
                kind="cpu_steal", severity=Severity.WARNING,
                description=f"CPU steal {s.cpu.steal_pct:.1f}% — noisy neighbour or oversubscribed hypervisor",
                evidence={"steal_pct": round(s.cpu.steal_pct, 1)},
            ))
        if s.cpu.iowait_pct is not None and s.cpu.iowait_pct > 20:
            out.append(Anomaly(
                kind="high_iowait", severity=Severity.WARNING,
                description=f"IO wait {s.cpu.iowait_pct:.1f}% — storage is the bottleneck",
                evidence={"iowait_pct": round(s.cpu.iowait_pct, 1)},
            ))
        if (s.cpu.load_15 is not None and s.cpu.cores
                and s.cpu.load_15 > s.cpu.cores * 2):
            out.append(Anomaly(
                kind="load_saturation", severity=Severity.CRITICAL,
                description=f"load15 {s.cpu.load_15:.1f} on {s.cpu.cores} cores",
                evidence={"load_15": s.cpu.load_15, "cores": s.cpu.cores},
            ))
        return out

    def _memory(self, s: ServerSnapshot, mem_hist: MetricSeries | None) -> list[Anomaly]:
        out: list[Anomaly] = []
        if s.memory.oom_events:
            out.append(Anomaly(
                kind="oom_events", severity=Severity.CRITICAL,
                description=f"{s.memory.oom_events} OOM kill(s) recorded",
                evidence={"oom_events": s.memory.oom_events},
            ))
        if (s.memory.swap_total_bytes and s.memory.swap_used_bytes
                and s.memory.swap_used_bytes / s.memory.swap_total_bytes > 0.8):
            out.append(Anomaly(
                kind="swap_pressure", severity=Severity.WARNING,
                description="swap more than 80% used",
                evidence={"swap_used_pct":
                          round(100 * s.memory.swap_used_bytes / s.memory.swap_total_bytes, 1)},
            ))
        if mem_hist and len(mem_hist.points) >= 10:
            slope = ml.linear_trend(mem_hist.values())
            if slope > 0.15:  # >0.15 %-points per sample, sustained
                out.append(Anomaly(
                    kind="memory_leak_suspect", severity=Severity.WARNING,
                    description="memory usage trending steadily upward — possible leak",
                    evidence={"slope_pct_per_sample": round(slope, 3)},
                ))
        return out

    def _disk(self, s: ServerSnapshot) -> list[Anomaly]:
        out: list[Anomaly] = []
        for fs in s.disk.filesystems:
            if fs.used_pct > 90:
                out.append(Anomaly(
                    kind="filesystem_full", severity=Severity.CRITICAL,
                    description=f"{fs.mount} at {fs.used_pct:.0f}%",
                    evidence={"mount": fs.mount, "used_pct": round(fs.used_pct, 1)},
                ))
        if s.disk.util_pct is not None and s.disk.util_pct > 90:
            out.append(Anomaly(
                kind="disk_saturation", severity=Severity.WARNING,
                description=f"disk util {s.disk.util_pct:.0f}%",
                evidence={"util_pct": s.disk.util_pct},
            ))
        if s.disk.smart_healthy is False or (s.disk.disk_errors or 0) > 0:
            out.append(Anomaly(
                kind="failing_disk", severity=Severity.CRITICAL,
                description="SMART failure or disk errors detected",
                evidence={"disk_errors": float(s.disk.disk_errors or 0)},
            ))
        return out

    def _network(self, s: ServerSnapshot) -> list[Anomaly]:
        out: list[Anomaly] = []
        if (s.network.dropped_packets or 0) > 1000 or (s.network.errors or 0) > 100:
            out.append(Anomaly(
                kind="nic_errors", severity=Severity.WARNING,
                description="elevated NIC errors/drops",
                evidence={"errors": float(s.network.errors or 0),
                          "dropped": float(s.network.dropped_packets or 0)},
            ))
        if s.network.packet_loss_pct is not None and s.network.packet_loss_pct > 1:
            out.append(Anomaly(
                kind="packet_loss", severity=Severity.WARNING,
                description=f"packet loss {s.network.packet_loss_pct:.1f}%",
                evidence={"loss_pct": s.network.packet_loss_pct},
            ))
        return out

    def _processes(self, s: ServerSnapshot) -> list[Anomaly]:
        out: list[Anomaly] = []
        if (s.processes.zombie_count or 0) > 5:
            out.append(Anomaly(
                kind="zombie_processes", severity=Severity.WARNING,
                description=f"{s.processes.zombie_count} zombie processes",
                evidence={"zombies": float(s.processes.zombie_count or 0)},
            ))
        if (s.processes.services_failed or 0) > 0:
            out.append(Anomaly(
                kind="failed_services", severity=Severity.WARNING,
                description=f"{s.processes.services_failed} failed service unit(s)",
                evidence={"failed": float(s.processes.services_failed or 0)},
            ))
        return out

    def _os(self, s: ServerSnapshot) -> list[Anomaly]:
        out: list[Anomaly] = []
        if s.os_state.time_synced is False:
            out.append(Anomaly(
                kind="time_drift", severity=Severity.WARNING,
                description="clock not NTP-synchronized (breaks Kerberos/TLS/logs)",
            ))
        if (s.os_state.updates_pending or 0) > 50:
            out.append(Anomaly(
                kind="patching_neglected", severity=Severity.WARNING,
                description=f"{s.os_state.updates_pending} pending updates",
                evidence={"updates": float(s.os_state.updates_pending or 0)},
            ))
        uptime_days = (s.identity.uptime_seconds or 0) / 86400
        if s.os_state.reboot_required and uptime_days > 90:
            out.append(Anomaly(
                kind="reboot_overdue", severity=Severity.WARNING,
                description=f"reboot required, uptime {uptime_days:.0f} days",
            ))
        if (s.activity.auth_events_30d or 0) > 200:
            out.append(Anomaly(
                kind="auth_failures", severity=Severity.CRITICAL,
                description=f"{s.activity.auth_events_30d} failed logons in 30d — possible brute force",
                evidence={"failures_30d": float(s.activity.auth_events_30d or 0)},
            ))
        return out

    def _ad(self, s: ServerSnapshot) -> list[Anomaly]:
        out: list[Anomaly] = []
        if s.ad is None:
            return out
        if s.ad.trust_ok is False:
            out.append(Anomaly(
                kind="ad_trust_broken", severity=Severity.CRITICAL,
                description="computer account disabled or trust relationship broken",
            ))
        if s.ad.replication_ok is False:
            out.append(Anomaly(
                kind="ad_replication_failure", severity=Severity.CRITICAL,
                description="AD replication failing",
            ))
        if s.ad.dns_registered is False:
            out.append(Anomaly(
                kind="dns_unregistered", severity=Severity.WARNING,
                description="computer object has no DNS host name",
            ))
        return out

    def _statistical(
        self, s: ServerSnapshot, history: dict[str, MetricSeries]
    ) -> list[Anomaly]:
        out: list[Anomaly] = []
        checks = {"cpu_pct": s.cpu.usage_pct, "net_rx": s.network.rx_bytes_per_sec}
        for metric, current in checks.items():
            series = history.get(metric)
            if current is None or series is None or len(series.points) < 12:
                continue
            baseline = ml.BehaviorBaseline(series.values())
            if baseline.is_anomalous(current):
                out.append(Anomaly(
                    kind=f"baseline_deviation:{metric}", severity=Severity.WARNING,
                    description=f"{metric} deviates >3σ from this host's baseline",
                    evidence={"current": round(current, 2)},
                ))
        return out
