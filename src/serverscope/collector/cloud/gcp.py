"""GCP Compute Engine collector: instance inventory + Cloud Monitoring CPU."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    HostIdentity,
    Platform,
    ServerSnapshot,
)


class GcpGceCollector(BaseCollector):
    _inventory: dict[str, dict[str, Any]] | None = None

    def hosts(self) -> list[str]:
        return self.target.hosts or ["__enumerate__"]

    async def discover(self) -> Any:
        inventory = await asyncio.to_thread(self._fetch_inventory)
        wanted = set(self.target.hosts) if self.target.hosts else None
        for name in inventory:
            if wanted is None or name in wanted:
                yield name

    async def collect_host(self, host: str) -> ServerSnapshot:
        inventory = await asyncio.to_thread(self._fetch_inventory)
        inst = inventory.get(host)
        if inst is None:
            raise CollectionError(host, "instance not found in project")
        return self._to_snapshot(inst)

    def _fetch_inventory(self) -> dict[str, dict[str, Any]]:
        if self._inventory is not None:
            return self._inventory
        try:
            from google.cloud import compute_v1, monitoring_v3
        except ImportError as exc:
            raise CollectionError(self.target.name, "google-cloud SDKs not installed (pip install serverscope[gcp])") from exc

        project = self.credential.project
        if not project:
            raise CollectionError(self.target.name, "gcp credential needs 'project'")
        client = compute_v1.InstancesClient()
        mon = monitoring_v3.MetricServiceClient()
        inventory: dict[str, dict[str, Any]] = {}
        agg = client.aggregated_list(request={"project": project})
        for _zone, response in agg:
            for inst in response.instances or []:
                cpu_avg = self._cpu_avg(mon, project, inst.name)
                inventory[inst.name] = {"instance": inst, "cpu_avg": cpu_avg}
        GcpGceCollector._inventory = inventory
        return inventory

    @staticmethod
    def _cpu_avg(mon: Any, project: str, name: str) -> float | None:
        try:
            from google.cloud import monitoring_v3

            now = datetime.now(UTC)
            interval = monitoring_v3.TimeInterval(
                {"end_time": now, "start_time": now - timedelta(days=7)}
            )
            results = mon.list_time_series(
                request={
                    "name": f"projects/{project}",
                    "filter": (
                        'metric.type="compute.googleapis.com/instance/cpu/utilization" '
                        f'AND metric.labels.instance_name="{name}"'
                    ),
                    "interval": interval,
                    "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                }
            )
            values = [p.value.double_value for ts in results for p in ts.points]
            return 100.0 * sum(values) / len(values) if values else None
        except Exception:  # noqa: BLE001 - metrics are best-effort
            return None

    def _to_snapshot(self, data: dict[str, Any]) -> ServerSnapshot:
        inst = data["instance"]
        running = inst.status == "RUNNING"
        return ServerSnapshot(
            collected_at=datetime.now(UTC),
            platform=Platform.GCP,
            identity=HostIdentity(
                hostname=inst.name,
                serial_number=str(inst.id),
                is_virtual=True,
                cloud_provider="gcp",
                tags={
                    **dict(inst.labels or {}),
                    "machine_type": inst.machine_type.rsplit("/", 1)[-1],
                    "status": inst.status,
                },
            ),
            cpu=CpuMetrics(usage_pct=data.get("cpu_avg"), avg_pct=data.get("cpu_avg")),
            activity=ActivitySignals(heartbeat_ok=running),
        )
