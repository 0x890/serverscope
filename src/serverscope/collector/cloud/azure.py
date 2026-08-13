"""Azure VM collector: ARM inventory + Azure Monitor CPU statistics."""
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


class AzureVmCollector(BaseCollector):
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
        vm = inventory.get(host)
        if vm is None:
            raise CollectionError(host, "VM not found in subscription")
        return self._to_snapshot(vm)

    def _fetch_inventory(self) -> dict[str, dict[str, Any]]:
        if self._inventory is not None:
            return self._inventory
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
            from azure.monitor.query import MetricsQueryClient
        except ImportError as exc:
            raise CollectionError(self.target.name, "azure SDKs not installed (pip install serverscope[azure])") from exc

        sub = self.credential.secret("subscription_id")
        if not sub:
            raise CollectionError(self.target.name, "azure credential needs subscription_id")
        cred = DefaultAzureCredential()
        compute = ComputeManagementClient(cred, sub)
        metrics = MetricsQueryClient(cred)
        inventory: dict[str, dict[str, Any]] = {}
        for vm in compute.virtual_machines.list_all():
            cpu_avg = cpu_peak = None
            try:
                resp = metrics.query_resource(
                    vm.id, metric_names=["Percentage CPU"],
                    timespan=timedelta(days=7), granularity=timedelta(hours=1),
                    aggregations=["Average", "Maximum"],
                )
                points = [
                    p for m in resp.metrics for ts in m.timeseries for p in ts.data
                    if p.average is not None
                ]
                if points:
                    cpu_avg = sum(p.average for p in points) / len(points)
                    cpu_peak = max(p.maximum or 0.0 for p in points)
            except Exception:  # noqa: BLE001 - metrics are best-effort
                pass
            inventory[vm.name] = {"vm": vm, "cpu_avg": cpu_avg, "cpu_peak": cpu_peak}
        AzureVmCollector._inventory = inventory
        return inventory

    def _to_snapshot(self, data: dict[str, Any]) -> ServerSnapshot:
        vm = data["vm"]
        os_disk = vm.storage_profile.os_disk if vm.storage_profile else None
        return ServerSnapshot(
            collected_at=datetime.now(UTC),
            platform=Platform.AZURE,
            identity=HostIdentity(
                hostname=vm.name,
                os_name=str(os_disk.os_type) if os_disk and os_disk.os_type else None,
                serial_number=vm.vm_id,
                is_virtual=True,
                cloud_provider="azure",
                tags={**(vm.tags or {}), "location": vm.location,
                      "size": vm.hardware_profile.vm_size if vm.hardware_profile else ""},
            ),
            cpu=CpuMetrics(
                usage_pct=data.get("cpu_avg"),
                avg_pct=data.get("cpu_avg"),
                peak_pct=data.get("cpu_peak"),
            ),
            activity=ActivitySignals(heartbeat_ok=data.get("cpu_avg") is not None),
        )
