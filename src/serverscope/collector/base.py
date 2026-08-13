"""Collector contract. A collector turns a target into ServerSnapshots."""
from __future__ import annotations

import abc
from collections.abc import AsyncIterator

from serverscope.core.config import CredentialConfig, TargetConfig
from serverscope.core.models import HostIdentity, ServerSnapshot


class CollectionError(RuntimeError):
    def __init__(self, host: str, message: str) -> None:
        super().__init__(f"{host}: {message}")
        self.host = host


class BaseCollector(abc.ABC):
    """One instance per configured target."""

    def __init__(self, target: TargetConfig, credential: CredentialConfig) -> None:
        self.target = target
        self.credential = credential

    @abc.abstractmethod
    def hosts(self) -> list[str]:
        """Hosts this collector will visit (may be discovered dynamically)."""

    @abc.abstractmethod
    async def collect_host(self, host: str) -> ServerSnapshot:
        """Collect a single host. Raise CollectionError on failure."""

    async def discover(self) -> AsyncIterator[str]:
        for host in self.hosts():
            yield host

    def apply_target_metadata(self, identity: HostIdentity) -> None:
        identity.environment = identity.environment or self.target.environment
        identity.business_unit = identity.business_unit or self.target.business_unit
        identity.owner = identity.owner or self.target.owner
        identity.tags.update(self.target.tags)
