"""Linux collector over SSH. Runs one composite script per host (2 round trips max)."""
from __future__ import annotations

from datetime import UTC, datetime

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.collector.linux import parsers
from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    DiskMetrics,
    HostIdentity,
    MemoryMetrics,
    NetworkMetrics,
    OsState,
    Platform,
    ProcessMetrics,
    ServerSnapshot,
)

# Single POSIX-sh script; every probe is best-effort so one failure never
# aborts the whole collection.
COLLECTION_SCRIPT = r"""
sec(){ printf '\n===%s===\n' "$1"; }
sec hostname; hostname 2>/dev/null
sec ip; hostname -I 2>/dev/null || ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}'
sec os_release; cat /etc/os-release 2>/dev/null
sec kernel; uname -r
sec arch; uname -m
sec vendor; cat /sys/class/dmi/id/sys_vendor 2>/dev/null
sec serial; cat /sys/class/dmi/id/product_serial 2>/dev/null
sec virt; systemd-detect-virt 2>/dev/null
sec uptime; cat /proc/uptime
sec timezone; timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null
sec loadavg; cat /proc/loadavg
sec cores; grep -c ^processor /proc/cpuinfo
sec mhz; grep -m1 'cpu MHz' /proc/cpuinfo 2>/dev/null | awk '{print $4}'
sec stat1; head -1 /proc/stat
sec diskstats1; cat /proc/diskstats
sec netdev1; cat /proc/net/dev
sleep 2
sec stat2; head -1 /proc/stat
sec diskstats2; cat /proc/diskstats
sec netdev2; cat /proc/net/dev
sec free; free -b 2>/dev/null
sec pgfault; grep -m1 '^pgfault' /proc/vmstat 2>/dev/null | awk '{print $2}'
sec oom; grep -m1 '^oom_kill' /proc/vmstat 2>/dev/null | awk '{print $2}'
sec df; df -PkT -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
sec ss_summary; ss -s 2>/dev/null
sec ss_listen; ss -tulnH 2>/dev/null
sec who; who 2>/dev/null | wc -l
sec last; last -n 20 -F 2>/dev/null | head -40
sec ps_cpu; ps aux --sort=-%cpu 2>/dev/null | head -12
sec ps_mem; ps aux --sort=-%mem 2>/dev/null | head -12
sec zombies; ps -eo stat 2>/dev/null | grep -c '^Z'
sec svc_running; systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l
sec svc_failed; systemctl list-units --type=service --state=failed --no-legend 2>/dev/null | wc -l
sec cron; { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } | grep -Ev '^\s*(#|$)' | head -50
sec reboot_required; test -f /var/run/reboot-required && echo yes || echo no
sec updates; { apt-get -s upgrade 2>/dev/null | grep -c ^Inst; } || { yum -q check-update 2>/dev/null | grep -vc '^$'; }
sec selinux; getenforce 2>/dev/null
sec apparmor; aa-enabled 2>/dev/null
sec ntp_sync; timedatectl show -p NTPSynchronized --value 2>/dev/null
sec firewall; if command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1; then { nft list ruleset 2>/dev/null || iptables -S 2>/dev/null; } | wc -l; fi
sec containers; if command -v docker >/dev/null 2>&1; then docker ps -q 2>/dev/null | wc -l; fi
sec k8s_pods; if command -v crictl >/dev/null 2>&1; then crictl ps -q 2>/dev/null | wc -l; fi
sec files_mod; find /var/log /home /opt -type f -mtime -7 2>/dev/null | head -500 | wc -l
exit 0
"""


class LinuxSSHCollector(BaseCollector):
    def hosts(self) -> list[str]:
        return self.target.hosts

    async def collect_host(self, host: str) -> ServerSnapshot:
        try:
            import asyncssh
        except ImportError as exc:
            raise CollectionError(host, "asyncssh not installed (pip install serverscope[linux])") from exc

        username = self.credential.username
        password = self.credential.secret("password")
        client_keys = (
            [self.credential.private_key_path] if self.credential.private_key_path else None
        )
        try:
            async with asyncssh.connect(
                host,
                username=username,
                password=password,
                client_keys=client_keys,
                known_hosts=None,
            ) as conn:
                result = await conn.run(COLLECTION_SCRIPT, check=False)
        except (OSError, asyncssh.Error) as exc:
            raise CollectionError(host, f"ssh failure: {exc}") from exc

        return self.build_snapshot(host, str(result.stdout or ""))

    def build_snapshot(self, host: str, output: str) -> ServerSnapshot:
        """Assemble a snapshot from raw script output (pure — unit testable)."""
        s = parsers.split_sections(output)
        errors: list[str] = []

        os_name, os_version = parsers.parse_os_release(s.get("os_release", ""))
        uptime_s, last_boot = parsers.parse_uptime(s.get("uptime", ""))
        virt = s.get("virt", "").strip()
        ip_parts = s.get("ip", "").split()
        identity = HostIdentity(
            hostname=s.get("hostname", "").strip() or host,
            ip=ip_parts[0] if ip_parts else None,
            os_name=os_name,
            os_version=os_version,
            kernel=s.get("kernel", "").strip() or None,
            architecture=s.get("arch", "").strip() or None,
            manufacturer=s.get("vendor", "").strip() or None,
            serial_number=s.get("serial", "").strip() or None,
            is_virtual=None if not virt else virt != "none",
            uptime_seconds=uptime_s,
            last_boot=last_boot,
            timezone=s.get("timezone", "").strip() or None,
        )

        cpu = CpuMetrics(cores=parsers.parse_int(s.get("cores", "")))
        load = parsers.parse_loadavg(s.get("loadavg", ""))
        if load:
            cpu.load_1, cpu.load_5, cpu.load_15 = load
        try:
            cpu.frequency_mhz = float(s.get("mhz", "").strip())
        except ValueError:
            pass
        pct = parsers.cpu_pct_from_stat_pair(s.get("stat1", ""), s.get("stat2", ""))
        cpu.usage_pct = pct.get("usage_pct")
        cpu.idle_pct = pct.get("idle_pct")
        cpu.iowait_pct = pct.get("iowait_pct")
        cpu.steal_pct = pct.get("steal_pct")

        free = parsers.parse_free(s.get("free", ""))
        memory = MemoryMetrics(
            total_bytes=free.get("total"),
            used_bytes=free.get("used"),
            swap_total_bytes=free.get("swap_total"),
            swap_used_bytes=free.get("swap_used"),
            cache_bytes=free.get("buff_cache"),
            oom_events=parsers.parse_int(s.get("oom", "")),
        )

        disk = DiskMetrics(filesystems=parsers.parse_df(s.get("df", "")))
        rates = parsers.disk_rates_from_pair(
            s.get("diskstats1", ""), s.get("diskstats2", ""), interval=2.0
        )
        disk.iops_read = rates.get("iops_read")
        disk.iops_write = rates.get("iops_write")
        disk.read_mbps = rates.get("read_mbps")
        disk.write_mbps = rates.get("write_mbps")

        net_rates = parsers.net_rates_from_pair(
            s.get("netdev1", ""), s.get("netdev2", ""), interval=2.0
        )
        network = NetworkMetrics(
            rx_bytes_per_sec=net_rates.get("rx_bytes_per_sec"),
            tx_bytes_per_sec=net_rates.get("tx_bytes_per_sec"),
            errors=int(net_rates.get("errors", 0)),
            dropped_packets=int(net_rates.get("dropped_packets", 0)),
            connections_established=parsers.parse_ss_summary(s.get("ss_summary", "")),
            open_ports=parsers.parse_ss_listen(s.get("ss_listen", "")),
            firewall_active=None if not s.get("firewall", "").strip()
            else (parsers.parse_int(s.get("firewall", "")) or 0) > 5,
        )

        cron_lines = [line for line in s.get("cron", "").splitlines() if line.strip()]
        processes = ProcessMetrics(
            top_cpu=parsers.parse_ps(s.get("ps_cpu", "")),
            top_memory=parsers.parse_ps(s.get("ps_mem", "")),
            zombie_count=parsers.parse_int(s.get("zombies", "")),
            services_running=parsers.parse_int(s.get("svc_running", "")),
            services_failed=parsers.parse_int(s.get("svc_failed", "")),
            cron_jobs=cron_lines[:50],
        )

        ntp = s.get("ntp_sync", "").strip()
        os_state = OsState(
            updates_pending=parsers.parse_int(s.get("updates", "")),
            reboot_required=s.get("reboot_required", "").strip() == "yes",
            selinux=s.get("selinux", "").strip() or None,
            apparmor=s.get("apparmor", "").strip() or None,
            time_synced=None if not ntp else ntp == "yes",
        )

        containers = parsers.parse_int(s.get("containers", ""))
        activity = ActivitySignals(
            last_user_login=parsers.parse_last_login(s.get("last", "")),
            interactive_sessions=parsers.parse_int(s.get("who", "")),
            cron_active=bool(cron_lines),
            containers_running=containers,
            k8s_pods_running=parsers.parse_int(s.get("k8s_pods", "")),
            files_modified_7d=parsers.parse_int(s.get("files_mod", "")),
        )

        return ServerSnapshot(
            collected_at=datetime.now(UTC),
            platform=Platform.LINUX,
            identity=identity,
            cpu=cpu,
            memory=memory,
            disk=disk,
            network=network,
            processes=processes,
            os_state=os_state,
            activity=activity,
            collection_errors=errors,
        )
