from __future__ import annotations

import csv
from pathlib import Path

from serverscope.report.base import ReportContext, Reporter


class CsvReporter(Reporter):
    name = "csv"
    extension = "csv"

    FIELDS = [
        "hostname", "platform", "classification", "health", "risk", "performance",
        "security", "availability", "maintenance", "idle_probability",
        "abandonment_probability", "recommendation",
    ]

    def render(self, context: ReportContext, output_dir: Path) -> Path:
        path = self.output_path(output_dir)
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=self.FIELDS)
            writer.writeheader()
            for r in context.results:
                writer.writerow({
                    "hostname": r.hostname,
                    "platform": r.platform.value,
                    "classification": r.classification.value,
                    "health": r.scores.health,
                    "risk": r.scores.risk,
                    "performance": r.scores.performance,
                    "security": r.scores.security,
                    "availability": r.scores.availability,
                    "maintenance": r.scores.maintenance,
                    "idle_probability": r.scores.idle_probability,
                    "abandonment_probability": r.scores.abandonment_probability,
                    "recommendation": r.recommendation,
                })
        return path
