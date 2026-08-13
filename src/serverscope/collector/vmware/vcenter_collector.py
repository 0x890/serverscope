"""VMware collector: inventories VMs from vCenter with quickstats + tools state."""
from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime
from typing import Any

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    HostIdentity,
    MemoryMetrics,
    Platform,
    ServerSnapshot,
)


class VCenterCollector(BaseCollector):
    _inventory: dict[str, dict[str, Any]] | None = None

    def hosts(self) -> list[str]:
        return self.target.hosts or ["__enumerate__"]

    async def discover(self) -> Any:
        inventory = await asyncio.to_thread(self._fetch_inventory)
        wanted = {h.lower() for h in self.target.hosts} if self.target.hosts else None
        for name in inventory:
            if wanted is None or name.lower() in wanted:
                yield name

    async def collect_host(self, host: str) -> ServerSnapshot:
        inventory = await asyncio.to_thread(self._fetch_inventory)
        vm = inventory.get(host)
        if vm is None:
            raise CollectionError(host, "VM not found in vCenter inventory")
        return self._to_snapshot(vm)

    def _fetch_inventory(self) -> dict[str, dict[str, Any]]:
        if self._inventory is not None:
            return self._inventory
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim
        except ImportError as exc:
            raise CollectionError(self.target.name, "pyvmomi not installed (pip install serverscope[vmware])") from exc

        ctx = ssl.create_default_context()
        if not self.credential.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            si = SmartConnect(
                host=self.credential.endpoint,
                user=self.credential.username,
                pwd=self.credential.secret("password"),
                sslContext=ctx,
            )
        except Exception as exc:  # noqa: BLE001
            raise CollectionError(self.target.name, f"vCenter connection failed: {exc}") from exc
        try:
            content = si.RetrieveContent()
            view = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )
            inventory: dict[str, dict[str, Any]] = {}
            for vm in view.view:
                cfg, summ, qs = vm.config, vm.summary, vm.summary.quickStats
                if cfg is None:
                    continue
                cpu_mhz_total = (summ.runtime.maxCpuUsage or 0) or None
                inventory[cfg.name] = {
                    "name": cfg.name,
                    "guest_os": cfg.guestFullName,
                    "uuid": cfg.uuid,
                    "power": str(summ.runtime.powerState),
                    "cores": cfg.hardware.numCPU,
                    "mem_mb": cfg.hardware.memoryMB,
                    "cpu_used_mhz": qs.overallCpuUsage,
                    "cpu_total_mhz": cpu_mhz_total,
                    "mem_used_mb": qs.guestMemoryUsage,
                    "tools": str(vm.guest.toolsRunningStatus) if vm.guest else None,
                    "ip": vm.guest.ipAddress if vm.guest else None,
                    "boot": summ.runtime.bootTime,
                    "host": summ.runtime.host.name if summ.runtime.host else None,
                }
            view.Destroy()
        finally:
            Disconnect(si)
        VCenterCollector._inventory = inventory
        return inventory

    def _to_snapshot(self, vm: dict[str, Any]) -> ServerSnapshot:
        now = datetime.now(UTC)
        boot = vm.get("boot")
        cpu_pct = None
        if vm.get("cpu_used_mhz") is not None and vm.get("cpu_total_mhz"):
            cpu_pct = 100.0 * vm["cpu_used_mhz"] / vm["cpu_total_mhz"]
        mem_total = (vm.get("mem_mb") or 0) * 1024 * 1024 or None
        mem_used = (vm.get("mem_used_mb") or 0) * 1024 * 1024 or None
        powered_on = vm.get("power") == "poweredOn"
        return ServerSnapshot(
            collected_at=now,
            platform=Platform.VMWARE,
            identity=HostIdentity(
                hostname=vm["name"],
                ip=vm.get("ip"),
                os_name=vm.get("guest_os"),
                serial_number=vm.get("uuid"),
                is_virtual=True,
                last_boot=boot,
                uptime_seconds=(now - boot).total_seconds() if boot else None,
                tags={"esxi_host": str(vm.get("host") or ""), "power": str(vm.get("power"))},
            ),
            cpu=CpuMetrics(usage_pct=cpu_pct, cores=vm.get("cores")),
            memory=MemoryMetrics(total_bytes=mem_total, used_bytes=mem_used),
            activity=ActivitySignals(
                vm_tools_active=vm.get("tools") == "guestToolsRunning",
                heartbeat_ok=powered_on,
            ),
        )
