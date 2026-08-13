"""YAML configuration with secret indirection (env / file / vault)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class SecretResolutionError(RuntimeError):
    pass


def resolve_secret(value: str | None) -> str | None:
    """Resolve ``env:``, ``file:`` and ``vault:`` secret references."""
    if value is None or ":" not in value:
        return value
    scheme, _, rest = value.partition(":")
    match scheme:
        case "env":
            resolved = os.environ.get(rest)
            if resolved is None:
                raise SecretResolutionError(f"environment variable {rest!r} is not set")
            return resolved
        case "file":
            return Path(rest).expanduser().read_text(encoding="utf-8").strip()
        case "vault":
            return _resolve_vault(rest)
        case _:
            return value


def _resolve_vault(ref: str) -> str:
    path, _, key = ref.partition("#")
    try:
        import hvac
    except ImportError as exc:  # pragma: no cover
        raise SecretResolutionError("vault: references require the 'hvac' package") from exc
    client = hvac.Client(url=os.environ.get("VAULT_ADDR"), token=os.environ.get("VAULT_TOKEN"))
    secret = client.read(path)
    if not secret:
        raise SecretResolutionError(f"vault path {path!r} not found")
    data = secret["data"].get("data", secret["data"])
    if key not in data:
        raise SecretResolutionError(f"key {key!r} not found at vault path {path!r}")
    return str(data[key])


class CredentialConfig(BaseModel):
    kind: str  # ssh | winrm | ldap | api | cloud
    username: str | None = None
    password: str | None = None
    private_key_path: str | None = None
    server: str | None = None
    endpoint: str | None = None
    base_dn: str | None = None
    transport: str = "ntlm"
    verify_ssl: bool = True
    token_name: str | None = None
    token_value: str | None = None
    profile: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    regions: list[str] = Field(default_factory=list)
    subscription_id: str | None = None
    project: str | None = None

    def secret(self, field: str) -> str | None:
        return resolve_secret(getattr(self, field))


class TargetConfig(BaseModel):
    name: str
    collector: str
    credential: str
    hosts: list[str] = Field(default_factory=list)
    environment: str | None = None
    business_unit: str | None = None
    owner: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class ConcurrencyConfig(BaseModel):
    max_parallel: int = 50
    rate_limit_per_sec: float = 20.0
    timeout_seconds: float = 60.0
    retries: int = 3
    retry_backoff_seconds: float = 2.0


class IdleConfig(BaseModel):
    cpu_avg_threshold_pct: float = 5.0
    hibernated_cpu_threshold_pct: float = 2.0
    io_iops_threshold: float = 5.0
    login_lookback_days: int = 90


class ThresholdConfig(BaseModel):
    overloaded_cpu_pct: float = 85.0
    overloaded_mem_pct: float = 90.0
    disk_full_pct: float = 90.0


class ScoringConfig(BaseModel):
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "performance": 0.30,
            "security": 0.25,
            "availability": 0.25,
            "maintenance": 0.20,
        }
    )
    idle: IdleConfig = Field(default_factory=IdleConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)

    @field_validator("weights")
    @classmethod
    def _weights_sum(cls, v: dict[str, float]) -> dict[str, float]:
        total = sum(v.values())
        if not 0.99 <= total <= 1.01:
            raise ValueError(f"scoring weights must sum to 1.0, got {total}")
        return v


class StorageConfig(BaseModel):
    path: str = "./serverscope.db"


class HistoryConfig(BaseModel):
    windows_days: list[int] = Field(default_factory=lambda: [1, 7, 30, 90, 365])


class ReportConfig(BaseModel):
    output_dir: str = "./reports"
    formats: list[str] = Field(default_factory=lambda: ["json", "csv", "markdown", "html"])


class DashboardConfig(BaseModel):
    output: str = "./reports/dashboard.html"


class AppConfig(BaseModel):
    storage: StorageConfig = Field(default_factory=StorageConfig)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    credentials: dict[str, CredentialConfig] = Field(default_factory=dict)
    targets: list[TargetConfig] = Field(default_factory=list)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)

    def credential_for(self, target: TargetConfig) -> CredentialConfig:
        try:
            return self.credentials[target.credential]
        except KeyError as exc:
            raise KeyError(
                f"target {target.name!r} references unknown credential {target.credential!r}"
            ) from exc


def load_config(path: str | Path) -> AppConfig:
    data: dict[str, Any] = yaml.safe_load(Path(path).expanduser().read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(data)
