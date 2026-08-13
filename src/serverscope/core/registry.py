"""Plugin registry. Collectors/reporters register via decorator or entry points."""
from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any, Generic, TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)


class Registry(Generic[T]):
    def __init__(self, entry_point_group: str) -> None:
        self._group = entry_point_group
        self._items: dict[str, type[T]] = {}
        self._loaded_entry_points = False

    def register(self, name: str) -> "type[T] | object":
        def decorator(cls: type[T]) -> type[T]:
            self._items[name] = cls
            return cls

        return decorator

    def add(self, name: str, cls: type[T]) -> None:
        self._items[name] = cls

    def get(self, name: str) -> type[T]:
        self._load_entry_points()
        try:
            return self._items[name]
        except KeyError as exc:
            raise KeyError(
                f"unknown plugin {name!r} in group {self._group!r}; "
                f"available: {sorted(self._items)}"
            ) from exc

    def names(self) -> list[str]:
        self._load_entry_points()
        return sorted(self._items)

    def _load_entry_points(self) -> None:
        if self._loaded_entry_points:
            return
        self._loaded_entry_points = True
        for ep in entry_points(group=self._group):
            if ep.name in self._items:
                continue
            try:
                self._items[ep.name] = ep.load()
            except Exception as exc:  # optional deps may be missing
                log.debug("skipping plugin %s: %s", ep.name, exc)


collector_registry: "Registry[Any]" = Registry("serverscope.collectors")
reporter_registry: "Registry[Any]" = Registry("serverscope.reporters")
