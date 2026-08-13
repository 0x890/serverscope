from __future__ import annotations

import json
from pathlib import Path

from serverscope.report.base import ReportContext, Reporter


class JsonReporter(Reporter):
    name = "json"
    extension = "json"

    def render(self, context: ReportContext, output_dir: Path) -> Path:
        path = self.output_path(output_dir)
        payload = {
            "generated_at": context.generated_at.isoformat(),
            "summary": {
                "total_servers": context.total,
                "average_health": context.avg_health,
                "classifications": dict(context.classification_counts),
                "decommission_candidates":
                    [r.hostname for r in context.decommission_candidates],
            },
            "servers": [
                {
                    **r.model_dump(mode="json"),
                    "performance_grade": r.performance_grade,
                    "security_grade": r.security_grade,
                    "availability_grade": r.availability_grade,
                }
                for r in context.results
            ],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path
