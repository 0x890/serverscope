"""AWS EC2 collector: instance inventory + CloudWatch CPU/network statistics."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    HostIdentity,
    NetworkMetrics,
    Platform,
    ServerSnapshot,
)


class AwsEc2Collector(BaseCollector):
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
            raise CollectionError(host, "instance not found")
        return self._to_snapshot(inst)

    def _session(self) -> Any:
        try:
            import boto3
        except ImportError as exc:
            raise CollectionError(self.target.name, "boto3 not installed (pip install serverscope[aws])") from exc
        if self.credential.profile:
            return boto3.Session(profile_name=self.credential.profile)
        return boto3.Session(
            aws_access_key_id=self.credential.secret("access_key"),
            aws_secret_access_key=self.credential.secret("secret_key"),
        )

    def _fetch_inventory(self) -> dict[str, dict[str, Any]]:
        if self._inventory is not None:
            return self._inventory
        session = self._session()
        inventory: dict[str, dict[str, Any]] = {}
        regions = self.credential.regions or [session.region_name or "us-east-1"]
        end = datetime.now(UTC)
        start = end - timedelta(days=7)
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            cw = session.client("cloudwatch", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for inst in reservation["Instances"]:
                        iid = inst["InstanceId"]
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        name = tags.get("Name", iid)
                        stats = self._cw_cpu(cw, iid, start, end)
                        inventory[name] = {
                            "instance": inst, "tags": tags, "region": region, **stats,
                        }
        AwsEc2Collector._inventory = inventory
        return inventory

    @staticmethod
    def _cw_cpu(cw: Any, iid: str, start: datetime, end: datetime) -> dict[str, float | None]:
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                StartTime=start, EndTime=end, Period=3600,
                Statistics=["Average", "Maximum"], Unit="Percent",
            )
            points = resp.get("Datapoints", [])
            if not points:
                return {"cpu_avg": None, "cpu_peak": None, "cpu_p95": None}
            avgs = sorted(p["Average"] for p in points)
            return {
                "cpu_avg": sum(avgs) / len(avgs),
                "cpu_peak": max(p["Maximum"] for p in points),
                "cpu_p95": avgs[int(len(avgs) * 0.95)] if len(avgs) > 1 else avgs[-1],
            }
        except Exception:  # noqa: BLE001 - metrics are best-effort
            return {"cpu_avg": None, "cpu_peak": None, "cpu_p95": None}

    def _to_snapshot(self, data: dict[str, Any]) -> ServerSnapshot:
        inst = data["instance"]
        tags = data["tags"]
        now = datetime.now(UTC)
        launch = inst.get("LaunchTime")
        running = inst.get("State", {}).get("Name") == "running"
        return ServerSnapshot(
            collected_at=now,
            platform=Platform.AWS,
            identity=HostIdentity(
                hostname=tags.get("Name", inst["InstanceId"]),
                ip=inst.get("PrivateIpAddress"),
                os_name=inst.get("PlatformDetails"),
                architecture=inst.get("Architecture"),
                serial_number=inst["InstanceId"],
                is_virtual=True,
                cloud_provider="aws",
                owner=tags.get("Owner"),
                business_unit=tags.get("BusinessUnit"),
                environment=tags.get("Environment"),
                tags={**tags, "region": data["region"],
                      "instance_type": inst.get("InstanceType", ""),
                      "state": inst.get("State", {}).get("Name", "")},
                last_boot=launch,
                uptime_seconds=(now - launch).total_seconds() if launch and running else None,
            ),
            cpu=CpuMetrics(
                usage_pct=data.get("cpu_avg"),
                avg_pct=data.get("cpu_avg"),
                p95_pct=data.get("cpu_p95"),
                peak_pct=data.get("cpu_peak"),
                cores=inst.get("CpuOptions", {}).get("CoreCount"),
            ),
            network=NetworkMetrics(),
            activity=ActivitySignals(heartbeat_ok=running),
        )
