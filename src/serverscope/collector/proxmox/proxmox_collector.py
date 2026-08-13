"""Proxmox VE collector: QEMU VMs + LXC containers with RRD utilisation history."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    DiskMetrics,
    HostIdentity,
    MemoryMetrics,
    NetworkMetrics,
    Platform,
    ServerSnapshot,
)


class ProxmoxCollector(BaseCollector):
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
        guest = inventory.get(host)
        if guest is None:
            raise CollectionError(host, "guest not found on Proxmox cluster")
        return self._to_snapshot(guest)

    def _api(self) -> Any:
        try:
            from proxmoxer import ProxmoxAPI
        except ImportError as exc:
            raise CollectionError(self.target.name, "proxmoxer not installed (pip install serverscope[proxmox])") from exc
        return ProxmoxAPI(
            self.credential.endpoint,
            user=self.credential.username,
            token_name=self.credential.token_name,
            token_value=self.credential.secret("token_value"),
            password=self.credential.secret("password"),
            verify_ssl=self.credential.verify_ssl,
        )

    def _fetch_inventory(self) -> dict[str, dict[str, Any]]:
        if self._inventory is not None:
            return self._inventory
        api = self._api()
        inventory: dict[str, dict[str, Any]] = {}
        try:
            for res in api.cluster.resources.get(type="vm"):
                name = res.get("name") or f"vmid-{res['vmid']}"
                rrd: list[dict[str, Any]] = []
                try:
                    rrd = api.nodes(res["node"])(res["type"])(res["vmid"]).rrddata.get(
                        timeframe="week"
                    )
                except Exception:  # noqa: BLE001 - RRD may be absent for stopped guests
                    pass
                inventory[name] = {**res, "rrd": rrd}
        except Exception as exc:  # noqa: BLE001
            raise CollectionError(self.target.name, f"proxmox API failure: {exc}") from exc
        ProxmoxCollector._inventory = inventory
        return inventory

    def _to_snapshot(self, g: dict[str, Any]) -> ServerSnapshot:
        now = datetime.now(UTC)
        rrd = g.get("rrd", [])
        cpu_samples = [100.0 * float(p["cpu"]) for p in rrd if p.get("cpu") is not None]
        avg = sum(cpu_samples) / len(cpu_samples) if cpu_samples else None
        p95 = sorted(cpu_samples)[int(len(cpu_samples) * 0.95)] if cpu_samples else None

        def rrd_avg(key: str) -> float | None:
            values = [float(p[key]) for p in rrd if p.get(key) is not None]
            return sum(values) / len(values) if values else None

        net_in, net_out = rrd_avg("netin"), rrd_avg("netout")
        disk_r, disk_w = rrd_avg("diskread"), rrd_avg("diskwrite")
        running = g.get("status") == "running"
        uptime = float(g.get("uptime") or 0) or None
        return ServerSnapshot(
            collected_at=now,
            platform=Platform.PROXMOX,
            identity=HostIdentity(
                hostname=str(g.get("name")),
                is_virtual=True,
                uptime_seconds=uptime,
                tags={
                    "vmid": str(g.get("vmid")),
                    "node": str(g.get("node")),
                    "type": str(g.get("type")),
                    "status": str(g.get("status")),
                },
            ),
            cpu=CpuMetrics(
                usage_pct=100.0 * float(g.get("cpu") or 0.0) if running else 0.0,
                avg_pct=avg,
                p95_pct=p95,
                peak_pct=max(cpu_samples) if cpu_samples else None,
                cores=g.get("maxcpu"),
            ),
            memory=MemoryMetrics(
                total_bytes=g.get("maxmem"),
                used_bytes=g.get("mem") if running else None,
            ),
            disk=DiskMetrics(
                read_mbps=disk_r / 1_048_576 if disk_r is not None else None,
                write_mbps=disk_w / 1_048_576 if disk_w is not None else None,
            ),
            network=NetworkMetrics(
                rx_bytes_per_sec=net_in, tx_bytes_per_sec=net_out,
            ),
            activity=ActivitySignals(heartbeat_ok=running),
        )
