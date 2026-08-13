"""Domain models shared across collectors, analyzers and reporters."""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field


class Platform(enum.StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    ACTIVE_DIRECTORY = "active_directory"
    VMWARE = "vmware"
    HYPERV = "hyperv"
    PROXMOX = "proxmox"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class Classification(enum.StrEnum):
    ACTIVE = "active"
    IDLE = "idle"
    UNDERUTILIZED = "underutilized"
    OVERLOADED = "overloaded"
    HIBERNATED = "hibernated"
    FORGOTTEN = "forgotten"
    ZOMBIE = "zombie"
    MISCONFIGURED = "misconfigured"
    ABNORMAL = "abnormal"
    DECOMMISSION_CANDIDATE = "decommission_candidate"
    UNKNOWN = "unknown"


class Severity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class HostIdentity(BaseModel):
    hostname: str
    ip: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    kernel: str | None = None
    architecture: str | None = None
    serial_number: str | None = None
    manufacturer: str | None = None
    is_virtual: bool | None = None
    cloud_provider: str | None = None
    owner: str | None = None
    business_unit: str | None = None
    environment: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    uptime_seconds: float | None = None
    last_boot: datetime | None = None
    timezone: str | None = None


class CpuMetrics(BaseModel):
    usage_pct: float | None = None
    avg_pct: float | None = None
    p95_pct: float | None = None
    peak_pct: float | None = None
    load_1: float | None = None
    load_5: float | None = None
    load_15: float | None = None
    steal_pct: float | None = None
    iowait_pct: float | None = None
    idle_pct: float | None = None
    cores: int | None = None
    frequency_mhz: float | None = None


class MemoryMetrics(BaseModel):
    total_bytes: int | None = None
    used_bytes: int | None = None
    swap_total_bytes: int | None = None
    swap_used_bytes: int | None = None
    cache_bytes: int | None = None
    buffers_bytes: int | None = None
    page_faults_per_sec: float | None = None
    oom_events: int | None = None
    pressure_pct: float | None = None

    @property
    def used_pct(self) -> float | None:
        if self.total_bytes and self.used_bytes is not None:
            return 100.0 * self.used_bytes / self.total_bytes
        return None


class FilesystemUsage(BaseModel):
    mount: str
    fstype: str | None = None
    size_bytes: int
    used_bytes: int
    growth_gb_per_day: float | None = None

    @property
    def used_pct(self) -> float:
        return 100.0 * self.used_bytes / self.size_bytes if self.size_bytes else 0.0


class DiskMetrics(BaseModel):
    filesystems: list[FilesystemUsage] = Field(default_factory=list)
    iops_read: float | None = None
    iops_write: float | None = None
    read_latency_ms: float | None = None
    write_latency_ms: float | None = None
    queue_length: float | None = None
    await_ms: float | None = None
    util_pct: float | None = None
    avg_request_kb: float | None = None
    read_mbps: float | None = None
    write_mbps: float | None = None
    trim_enabled: bool | None = None
    disk_errors: int | None = None
    smart_healthy: bool | None = None


class NetworkMetrics(BaseModel):
    rx_bytes_per_sec: float | None = None
    tx_bytes_per_sec: float | None = None
    bandwidth_mbps: float | None = None
    packet_loss_pct: float | None = None
    dropped_packets: int | None = None
    errors: int | None = None
    nic_errors: int | None = None
    connections_established: int | None = None
    connections_per_hour: float | None = None
    packets_per_sec: float | None = None
    open_ports: list[int] = Field(default_factory=list)
    firewall_active: bool | None = None
    top_talkers: list[str] = Field(default_factory=list)


class ProcessInfo(BaseModel):
    pid: int
    name: str
    cpu_pct: float = 0.0
    mem_pct: float = 0.0
    user: str | None = None


class ProcessMetrics(BaseModel):
    top_cpu: list[ProcessInfo] = Field(default_factory=list)
    top_memory: list[ProcessInfo] = Field(default_factory=list)
    zombie_count: int | None = None
    services_running: int | None = None
    services_failed: int | None = None
    daemons: list[str] = Field(default_factory=list)
    scheduled_tasks: list[str] = Field(default_factory=list)
    cron_jobs: list[str] = Field(default_factory=list)


class OsState(BaseModel):
    updates_pending: int | None = None
    reboot_required: bool | None = None
    kernel_age_days: int | None = None
    selinux: str | None = None
    apparmor: str | None = None
    bitlocker: bool | None = None
    antivirus: str | None = None
    edr: str | None = None
    time_synced: bool | None = None
    ntp_offset_ms: float | None = None


class ADInfo(BaseModel):
    distinguished_name: str | None = None
    ou: str | None = None
    last_logon: datetime | None = None
    last_logon_timestamp: datetime | None = None
    password_age_days: int | None = None
    trust_ok: bool | None = None
    gpos: list[str] = Field(default_factory=list)
    domain: str | None = None
    replication_ok: bool | None = None
    dns_registered: bool | None = None


class ActivitySignals(BaseModel):
    """Signals feeding the idle / abandonment scoring engine."""

    last_user_login: datetime | None = None
    interactive_sessions: int | None = None
    ssh_sessions: int | None = None
    rdp_sessions: int | None = None
    logins_90d: int | None = None
    cron_active: bool | None = None
    scheduled_tasks_active: bool | None = None
    db_active: bool | None = None
    app_log_activity: bool | None = None
    web_requests_per_day: float | None = None
    auth_events_30d: int | None = None
    files_modified_7d: int | None = None
    registry_changes_7d: int | None = None
    ad_logons_30d: int | None = None
    dns_queries_per_day: float | None = None
    dhcp_lease_active: bool | None = None
    monitoring_active: bool | None = None
    backup_last: datetime | None = None
    security_events_30d: int | None = None
    cert_renewed_recently: bool | None = None
    heartbeat_ok: bool | None = None
    vm_tools_active: bool | None = None
    containers_running: int | None = None
    k8s_pods_running: int | None = None


class ServerSnapshot(BaseModel):
    collected_at: datetime
    platform: Platform
    identity: HostIdentity
    cpu: CpuMetrics = Field(default_factory=CpuMetrics)
    memory: MemoryMetrics = Field(default_factory=MemoryMetrics)
    disk: DiskMetrics = Field(default_factory=DiskMetrics)
    network: NetworkMetrics = Field(default_factory=NetworkMetrics)
    processes: ProcessMetrics = Field(default_factory=ProcessMetrics)
    os_state: OsState = Field(default_factory=OsState)
    ad: ADInfo | None = None
    activity: ActivitySignals = Field(default_factory=ActivitySignals)
    raw: dict[str, str] = Field(default_factory=dict)
    collection_errors: list[str] = Field(default_factory=list)


class MetricPoint(BaseModel):
    ts: datetime
    value: float


class MetricSeries(BaseModel):
    name: str
    points: list[MetricPoint] = Field(default_factory=list)

    def values(self) -> list[float]:
        return [p.value for p in self.points]


class Anomaly(BaseModel):
    kind: str
    severity: Severity
    description: str
    evidence: dict[str, float | str] = Field(default_factory=dict)


class Scores(BaseModel):
    health: float = 0.0
    risk: float = 0.0
    criticality: float = 0.0
    business_impact: float = 0.0
    performance: float = 0.0
    security: float = 0.0
    availability: float = 0.0
    maintenance: float = 0.0
    idle_probability: float = 0.0
    abandonment_probability: float = 0.0


def grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


class AnalysisResult(BaseModel):
    hostname: str
    platform: Platform
    scores: Scores
    classification: Classification
    anomalies: list[Anomaly] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommendation: str = ""

    @property
    def performance_grade(self) -> str:
        return grade(self.scores.performance)

    @property
    def security_grade(self) -> str:
        return grade(self.scores.security)

    @property
    def availability_grade(self) -> str:
        return grade(self.scores.availability)
