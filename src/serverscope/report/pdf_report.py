from __future__ import annotations

from pathlib import Path

from serverscope.report.base import ReportContext, Reporter
from serverscope.report.html_report import HtmlReporter


class PdfReporter(Reporter):
    name = "pdf"
    extension = "pdf"

    def render(self, context: ReportContext, output_dir: Path) -> Path:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError("weasyprint required: pip install serverscope[pdf]") from exc
        html_path = HtmlReporter().render(context, output_dir)
        path = self.output_path(output_dir)
        HTML(filename=str(html_path)).write_pdf(str(path))
        return path
