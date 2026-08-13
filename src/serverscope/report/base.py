"""Report contract and shared context assembly."""
from __future__ import annotations

import abc
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from serverscope.core.models import AnalysisResult, Classification, ServerSnapshot, Severity


@dataclass
class ReportContext:
    generated_at: datetime
    snapshots: dict[str, ServerSnapshot]
    results: list[AnalysisResult]
    classification_counts: Counter[str] = field(default_factory=Counter)

    @classmethod
    def build(
        cls, snapshots: list[ServerSnapshot], results: list[AnalysisResult]
    ) -> "ReportContext":
        return cls(
            generated_at=datetime.now(UTC),
            snapshots={s.identity.hostname: s for s in snapshots},
            results=results,
            classification_counts=Counter(r.classification.value for r in results),
        )

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def avg_health(self) -> float:
        return (
            round(sum(r.scores.health for r in self.results) / len(self.results), 1)
            if self.results else 0.0
        )

    @property
    def decommission_candidates(self) -> list[AnalysisResult]:
        return [r for r in self.results
                if r.classification == Classification.DECOMMISSION_CANDIDATE]

    @property
    def idle_servers(self) -> list[AnalysisResult]:
        return [r for r in self.results if r.scores.idle_probability >= 60]

    @property
    def critical_anomalies(self) -> list[tuple[str, str]]:
        return [
            (r.hostname, a.description)
            for r in self.results
            for a in r.anomalies
            if a.severity == Severity.CRITICAL
        ]

    @property
    def top_risks(self) -> list[AnalysisResult]:
        return sorted(self.results, key=lambda r: r.scores.risk, reverse=True)[:10]

    @property
    def quick_wins(self) -> list[AnalysisResult]:
        """High idle probability + low criticality = safe savings."""
        return sorted(
            (r for r in self.results
             if r.scores.idle_probability >= 70 and r.scores.criticality < 50),
            key=lambda r: r.scores.idle_probability, reverse=True,
        )[:10]


class Reporter(abc.ABC):
    name: str = "base"
    extension: str = ""

    @abc.abstractmethod
    def render(self, context: ReportContext, output_dir: Path) -> Path:
        """Write the report and return its path."""

    def output_path(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return output_dir / f"serverscope-{stamp}.{self.extension}"
