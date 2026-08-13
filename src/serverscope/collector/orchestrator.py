"""Async fan-out over all targets/hosts with concurrency, rate limit and retries.

Scales from 10 to 10,000 hosts: a bounded semaphore caps in-flight sessions,
a token bucket caps new-connection rate, and per-host retries isolate failures.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.config import AppConfig
from serverscope.core.models import ServerSnapshot
from serverscope.core.registry import collector_registry
from serverscope.core.retry import RateLimiter, retry_async
from serverscope.core.storage import MetricStore

log = logging.getLogger(__name__)


@dataclass
class CollectionRun:
    snapshots: list[ServerSnapshot] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)


class Orchestrator:
    def __init__(self, config: AppConfig, store: MetricStore) -> None:
        self.config = config
        self.store = store
        cc = config.concurrency
        self._semaphore = asyncio.Semaphore(cc.max_parallel)
        self._limiter = RateLimiter(cc.rate_limit_per_sec)

    def _build_collectors(self, only_targets: set[str] | None = None) -> list[BaseCollector]:
        collectors: list[BaseCollector] = []
        for target in self.config.targets:
            if only_targets and target.name not in only_targets:
                continue
            cls = collector_registry.get(target.collector)
            collectors.append(cls(target, self.config.credential_for(target)))
        return collectors

    async def run(self, only_targets: set[str] | None = None) -> CollectionRun:
        run = CollectionRun()
        tasks: list[asyncio.Task[None]] = []
        for collector in self._build_collectors(only_targets):
            async for host in collector.discover():
                tasks.append(asyncio.create_task(self._collect_one(collector, host, run)))
        if tasks:
            await asyncio.gather(*tasks)
        log.info("collection finished: %d ok, %d failed", len(run.snapshots), len(run.failures))
        return run

    async def _collect_one(self, collector: BaseCollector, host: str, run: CollectionRun) -> None:
        cc = self.config.concurrency
        async with self._semaphore:
            await self._limiter.acquire()
            try:
                snapshot = await retry_async(
                    lambda: collector.collect_host(host),
                    retries=cc.retries,
                    backoff_seconds=cc.retry_backoff_seconds,
                    timeout_seconds=cc.timeout_seconds,
                    what=f"collect {host}",
                )
            except (CollectionError, Exception) as exc:  # noqa: BLE001
                log.error("collection failed for %s: %s", host, exc)
                run.failures[host] = str(exc)
                return
        collector.apply_target_metadata(snapshot.identity)
        self.store.save_snapshot(snapshot)
        run.snapshots.append(snapshot)
