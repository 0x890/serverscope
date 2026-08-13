from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from serverscope.report.base import ReportContext, Reporter


class HtmlReporter(Reporter):
    name = "html"
    extension = "html"

    def render(self, context: ReportContext, output_dir: Path) -> Path:
        env = Environment(
            loader=PackageLoader("serverscope.report", "templates"),
            autoescape=select_autoescape(["html"]),
        )
        html = env.get_template("report.html.j2").render(ctx=context)
        path = self.output_path(output_dir)
        path.write_text(html, encoding="utf-8")
        return path
