"""Windows collector: one PowerShell payload over WinRM returning JSON."""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.models import (
    ActivitySignals,
    CpuMetrics,
    DiskMetrics,
    FilesystemUsage,
    HostIdentity,
    MemoryMetrics,
    NetworkMetrics,
    OsState,
    Platform,
    ProcessInfo,
    ProcessMetrics,
    ServerSnapshot,
)

POWERSHELL_PAYLOAD = r"""
$ErrorActionPreference = 'SilentlyContinue'
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
$cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    ForEach-Object { @{ mount=$_.DeviceID; fstype=$_.FileSystem; size=$_.Size; free=$_.FreeSpace } }
$procsCpu = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id,ProcessName,CPU,WorkingSet
$procsMem = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Id,ProcessName,CPU,WorkingSet
$svcRunning = (Get-Service | Where-Object Status -eq 'Running').Count
$svcStopped = (Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'}).Count
$tasks = (Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object -First 100).TaskName
$pendingReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$updates = 0
try { $s = New-Object -ComObject Microsoft.Update.Session
      $updates = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'").Updates.Count } catch {}
$lastLogonEvt = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
$authFail = 0
try { $authFail = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 500).Count } catch {}
$rdpSessions = (query user 2>$null | Measure-Object -Line).Lines - 1
$bde = 0
try { $bde = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus } catch {}
$av = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct).displayName -join ','
$fw = (Get-NetFirewallProfile | Where-Object Enabled -eq $true).Count
$ports = (Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique)
$estab = (Get-NetTCPConnection -State Established).Count
$w32tm = (w32tm /query /status 2>$null | Out-String)
@{
  hostname=$env:COMPUTERNAME; os=$os.Caption; version=$os.Version
  arch=$os.OSArchitecture; serial=$bios.SerialNumber; manufacturer=$cs.Manufacturer
  model=$cs.Model; domain=$cs.Domain
  lastBoot=$os.LastBootUpTime.ToUniversalTime().ToString('o')
  tz=(Get-TimeZone).Id
  cpuPct=$cpuLoad; cores=$cs.NumberOfLogicalProcessors; mhz=$cpu.MaxClockSpeed
  memTotal=$os.TotalVisibleMemorySize*1KB; memFree=$os.FreePhysicalMemory*1KB
  swapTotal=$os.TotalVirtualMemorySize*1KB; swapFree=$os.FreeVirtualMemory*1KB
  disks=$disks
  procsCpu=$procsCpu; procsMem=$procsMem
  svcRunning=$svcRunning; svcFailed=$svcStopped; tasks=$tasks
  pendingReboot=$pendingReboot; updates=$updates
  lastLogon=$(if ($lastLogonEvt) { $lastLogonEvt.TimeCreated.ToUniversalTime().ToString('o') })
  authFail30d=$authFail; rdp=$rdpSessions
  bitlocker=($bde -eq 1); antivirus=$av; firewallProfiles=$fw
  openPorts=$ports; estab=$estab; timeSynced=($w32tm -match 'Source:')
} | ConvertTo-Json -Depth 4 -Compress
"""


class WindowsWinRMCollector(BaseCollector):
    def hosts(self) -> list[str]:
        return self.target.hosts

    async def collect_host(self, host: str) -> ServerSnapshot:
        return await asyncio.to_thread(self._collect_sync, host)

    def _collect_sync(self, host: str) -> ServerSnapshot:
        try:
            import winrm
        except ImportError as exc:
            raise CollectionError(host, "pywinrm not installed (pip install serverscope[windows])") from exc

        try:
            session = winrm.Session(
                f"http://{host}:5985/wsman",
                auth=(self.credential.username or "", self.credential.secret("password") or ""),
                transport=self.credential.transport,
            )
            result = session.run_ps(POWERSHELL_PAYLOAD)
        except Exception as exc:  # noqa: BLE001 - pywinrm raises many types
            raise CollectionError(host, f"winrm failure: {exc}") from exc
        if result.status_code != 0:
            raise CollectionError(host, f"powershell failed: {result.std_err[:500]!r}")
        try:
            data: dict[str, Any] = json.loads(result.std_out.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            raise CollectionError(host, f"invalid JSON payload: {exc}") from exc
        return self.build_snapshot(host, data)

    def build_snapshot(self, host: str, d: dict[str, Any]) -> ServerSnapshot:
        now = datetime.now(UTC)
        last_boot = _dt(d.get("lastBoot"))
        mem_total = _int(d.get("memTotal"))
        mem_free = _int(d.get("memFree"))
        swap_total = _int(d.get("swapTotal"))
        swap_free = _int(d.get("swapFree"))

        filesystems = [
            FilesystemUsage(
                mount=fs["mount"], fstype=fs.get("fstype"),
                size_bytes=_int(fs.get("size")) or 0,
                used_bytes=(_int(fs.get("size")) or 0) - (_int(fs.get("free")) or 0),
            )
            for fs in d.get("disks") or []
            if fs.get("size")
        ]

        return ServerSnapshot(
            collected_at=now,
            platform=Platform.WINDOWS,
            identity=HostIdentity(
                hostname=str(d.get("hostname") or host),
                os_name=d.get("os"),
                os_version=d.get("version"),
                architecture=d.get("arch"),
                serial_number=d.get("serial"),
                manufacturer=d.get("manufacturer"),
                is_virtual="virtual" in str(d.get("model", "")).lower() or None,
                last_boot=last_boot,
                uptime_seconds=(now - last_boot).total_seconds() if last_boot else None,
                timezone=d.get("tz"),
                tags={"domain": str(d.get("domain"))} if d.get("domain") else {},
            ),
            cpu=CpuMetrics(
                usage_pct=_float(d.get("cpuPct")),
                cores=_int(d.get("cores")),
                frequency_mhz=_float(d.get("mhz")),
            ),
            memory=MemoryMetrics(
                total_bytes=mem_total,
                used_bytes=(mem_total - mem_free) if mem_total and mem_free is not None else None,
                swap_total_bytes=swap_total,
                swap_used_bytes=(swap_total - swap_free)
                if swap_total and swap_free is not None else None,
            ),
            disk=DiskMetrics(filesystems=filesystems),
            network=NetworkMetrics(
                open_ports=sorted({int(p) for p in d.get("openPorts") or []}),
                connections_established=_int(d.get("estab")),
                firewall_active=(_int(d.get("firewallProfiles")) or 0) > 0,
            ),
            processes=ProcessMetrics(
                top_cpu=_procs(d.get("procsCpu")),
                top_memory=_procs(d.get("procsMem")),
                services_running=_int(d.get("svcRunning")),
                services_failed=_int(d.get("svcFailed")),
                scheduled_tasks=[str(t) for t in d.get("tasks") or []],
            ),
            os_state=OsState(
                updates_pending=_int(d.get("updates")),
                reboot_required=bool(d.get("pendingReboot")),
                bitlocker=bool(d.get("bitlocker")),
                antivirus=d.get("antivirus") or None,
                time_synced=bool(d.get("timeSynced")),
            ),
            activity=ActivitySignals(
                last_user_login=_dt(d.get("lastLogon")),
                rdp_sessions=max(0, _int(d.get("rdp")) or 0),
                auth_events_30d=_int(d.get("authFail30d")),
                scheduled_tasks_active=bool(d.get("tasks")),
            ),
        )


def _int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _float(v: Any) -> float | None:
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _dt(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None


def _procs(items: Any) -> list[ProcessInfo]:
    out: list[ProcessInfo] = []
    for p in items or []:
        try:
            out.append(
                ProcessInfo(
                    pid=int(p.get("Id", 0)),
                    name=str(p.get("ProcessName", "?")),
                    cpu_pct=float(p.get("CPU") or 0.0),
                    mem_pct=0.0,
                )
            )
        except (TypeError, ValueError):
            continue
    return out
