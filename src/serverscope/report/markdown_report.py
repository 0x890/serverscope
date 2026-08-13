from __future__ import annotations

from pathlib import Path

from serverscope.report.base import ReportContext, Reporter


class MarkdownReporter(Reporter):
    name = "markdown"
    extension = "md"

    def render(self, context: ReportContext, output_dir: Path) -> Path:
        path = self.output_path(output_dir)
        lines: list[str] = [
            "# ServerScope — Infrastructure Utilization Report",
            f"\nGenerated: {context.generated_at:%Y-%m-%d %H:%M UTC}",
            "\n## Executive Summary\n",
            f"- Servers analyzed: **{context.total}**",
            f"- Average health score: **{context.avg_health}/100**",
            f"- Decommission candidates: **{len(context.decommission_candidates)}**",
            f"- Idle servers (≥60%): **{len(context.idle_servers)}**",
            f"- Critical anomalies: **{len(context.critical_anomalies)}**",
            "\n### Classification breakdown\n",
        ]
        for cls, count in context.classification_counts.most_common():
            lines.append(f"- {cls}: {count}")

        lines.append("\n## Server Inventory\n")
        lines.append("| Server | Platform | Class | Health | Idle % | Abandon % | Perf | Sec | Avail |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for r in context.results:
            lines.append(
                f"| {r.hostname} | {r.platform.value} | {r.classification.value} "
                f"| {r.scores.health} | {r.scores.idle_probability} "
                f"| {r.scores.abandonment_probability} | {r.performance_grade} "
                f"| {r.security_grade} | {r.availability_grade} |"
            )

        if context.decommission_candidates:
            lines.append("\n## Decommission Candidates\n")
            for r in context.decommission_candidates:
                lines.append(f"### {r.hostname}")
                lines.append(f"- Abandonment probability: **{r.scores.abandonment_probability}%**")
                for reason in r.reasons:
                    lines.append(f"- {reason}")
                lines.append(f"- **Recommendation:** {r.recommendation}\n")

        if context.top_risks:
            lines.append("\n## Top Risks\n")
            for r in context.top_risks:
                lines.append(f"- **{r.hostname}** (risk {r.scores.risk}): "
                             + (r.anomalies[0].description if r.anomalies else r.recommendation))

        if context.quick_wins:
            lines.append("\n## Quick Wins\n")
            for r in context.quick_wins:
                lines.append(f"- **{r.hostname}** — idle {r.scores.idle_probability}%, "
                             f"low criticality ({r.scores.criticality})")

        if context.critical_anomalies:
            lines.append("\n## Critical Findings\n")
            for host, desc in context.critical_anomalies:
                lines.append(f"- **{host}**: {desc}")

        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
