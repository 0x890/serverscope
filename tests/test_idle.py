from __future__ import annotations

from serverscope.analyzer.idle import IdleScorer
from serverscope.core.config import IdleConfig
from serverscope.core.models import ServerSnapshot


def scorer() -> IdleScorer:
    return IdleScorer(IdleConfig())


def test_active_server_low_idle(active_snapshot: ServerSnapshot) -> None:
    prob, _ = scorer().idle_probability(active_snapshot)
    assert prob < 40


def test_abandoned_server_high_idle(abandoned_snapshot: ServerSnapshot) -> None:
    prob, reasons = scorer().idle_probability(abandoned_snapshot)
    assert prob > 80
    assert reasons


def test_abandonment_boosted_by_stale_login(abandoned_snapshot: ServerSnapshot) -> None:
    prob, reasons = scorer().abandonment_probability(abandoned_snapshot)
    assert prob > 75
    assert any("no user login" in r for r in reasons)


def test_hibernation_requires_low_cpu(
    active_snapshot: ServerSnapshot, abandoned_snapshot: ServerSnapshot
) -> None:
    s = scorer()
    assert s.hibernation_probability(abandoned_snapshot) > 80
    # active server with 25% CPU cannot be hibernated
    assert s.hibernation_probability(active_snapshot) < 40


def test_no_signals_returns_zero() -> None:
    from datetime import UTC, datetime

    from serverscope.core.models import HostIdentity, Platform

    empty = ServerSnapshot(
        collected_at=datetime.now(UTC),
        platform=Platform.LINUX,
        identity=HostIdentity(hostname="empty"),
    )
    prob, _ = scorer().idle_probability(empty)
    assert prob == 0.0
