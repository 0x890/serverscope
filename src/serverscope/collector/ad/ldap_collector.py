"""Active Directory collector: enumerates computer objects over LDAP(S).

Yields one snapshot per computer object — AD-side signals (lastLogonTimestamp,
pwdLastSet, OU, DNS registration) that feed the forgotten/abandoned scoring even
when the OS itself is unreachable.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from serverscope.collector.base import BaseCollector, CollectionError
from serverscope.core.models import (
    ActivitySignals,
    ADInfo,
    HostIdentity,
    Platform,
    ServerSnapshot,
)

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)


def filetime_to_dt(value: int | None) -> datetime | None:
    if not value:
        return None
    return _EPOCH_1601 + timedelta(microseconds=int(value) / 10)


class ActiveDirectoryCollector(BaseCollector):
    _cache: dict[str, dict[str, Any]] | None = None

    def hosts(self) -> list[str]:
        return self.target.hosts or ["__enumerate__"]

    async def collect_host(self, host: str) -> ServerSnapshot:
        entries = await asyncio.to_thread(self._query)
        if host != "__enumerate__":
            entry = entries.get(host.upper())
            if entry is None:
                raise CollectionError(host, "computer object not found in AD")
            return self._to_snapshot(entry)
        # Single-shot enumeration mode: orchestrator gets one snapshot per call;
        # discover() below expands to concrete names once queried.
        raise CollectionError(host, "enumeration handled via discover()")

    async def discover(self) -> Any:
        if self.target.hosts:
            for h in self.target.hosts:
                yield h
            return
        entries = await asyncio.to_thread(self._query)
        for name in entries:
            yield name

    def _query(self) -> dict[str, dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        try:
            import ldap3
        except ImportError as exc:
            raise CollectionError(self.target.name, "ldap3 not installed (pip install serverscope[ad])") from exc

        server_uri = self.credential.server or self.credential.endpoint
        if not server_uri or not self.credential.base_dn:
            raise CollectionError(self.target.name, "ldap credential needs 'server' and 'base_dn'")
        server = ldap3.Server(server_uri, get_info=ldap3.NONE)
        conn = ldap3.Connection(
            server,
            user=self.credential.username,
            password=self.credential.secret("password"),
            authentication=ldap3.NTLM if "\\" in (self.credential.username or "") else ldap3.SIMPLE,
            auto_bind=True,
        )
        conn.search(
            search_base=self.credential.base_dn,
            search_filter="(objectClass=computer)",
            attributes=[
                "cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                "lastLogon", "lastLogonTimestamp", "pwdLastSet", "whenCreated",
                "distinguishedName", "userAccountControl",
            ],
            paged_size=500,
        )
        result: dict[str, dict[str, Any]] = {}
        for entry in conn.entries:
            attrs = entry.entry_attributes_as_dict
            name = str(attrs.get("cn", [""])[0]).upper()
            if name:
                result[name] = attrs
        conn.unbind()
        ActiveDirectoryCollector._cache = result
        return result

    def _to_snapshot(self, attrs: dict[str, Any]) -> ServerSnapshot:
        def first(key: str) -> Any:
            v = attrs.get(key) or [None]
            return v[0] if isinstance(v, list) else v

        dn = str(first("distinguishedName") or "")
        ou = ",".join(p for p in dn.split(",") if p.startswith("OU=")) or None
        last_logon = _to_dt(first("lastLogon"))
        last_logon_ts = _to_dt(first("lastLogonTimestamp"))
        pwd_last_set = _to_dt(first("pwdLastSet"))
        uac = _as_int(first("userAccountControl")) or 0
        now = datetime.now(UTC)

        return ServerSnapshot(
            collected_at=now,
            platform=Platform.ACTIVE_DIRECTORY,
            identity=HostIdentity(
                hostname=str(first("cn")),
                os_name=str(first("operatingSystem") or "") or None,
                os_version=str(first("operatingSystemVersion") or "") or None,
                tags={"dns_hostname": str(first("dNSHostName") or "")},
            ),
            ad=ADInfo(
                distinguished_name=dn or None,
                ou=ou,
                last_logon=last_logon,
                last_logon_timestamp=last_logon_ts,
                password_age_days=(now - pwd_last_set).days if pwd_last_set else None,
                trust_ok=not bool(uac & 0x2),  # ACCOUNTDISABLE
                dns_registered=bool(first("dNSHostName")),
            ),
            activity=ActivitySignals(
                last_user_login=last_logon_ts or last_logon,
                ad_logons_30d=1 if (last_logon_ts and (now - last_logon_ts).days <= 30) else 0,
            ),
        )


def _to_dt(v: Any) -> datetime | None:
    """ldap3 may return AD timestamps pre-converted to datetime or as raw FILETIME."""
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    return filetime_to_dt(_as_int(v))


def _as_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
