from __future__ import annotations

import json
from pathlib import Path

from serverscope.analyzer.anomaly import AnomalyDetector
from serverscope.analyzer.scoring import ScoringEngine
from serverscope.core.config import ScoringConfig, load_config
from serverscope.core.storage import MetricStore
from serverscope.dashboard.builder import DashboardBuilder
from serverscope.report.base import ReportContext
from serverscope.report.csv_report import CsvReporter
from serverscope.report.html_report import HtmlReporter
from serverscope.report.json_report import JsonReporter
from serverscope.report.markdown_report import MarkdownReporter
from tests.conftest import make_abandoned_snapshot, make_snapshot


def _context() -> ReportContext:
    snaps = [make_snapshot(), make_abandoned_snapshot()]
    engine = ScoringEngine(ScoringConfig())
    detector = AnomalyDetector()
    results = [engine.score(s, detector.detect(s)) for s in snaps]
    return ReportContext.build(snaps, results)


def test_store_roundtrip(tmp_path: Path) -> None:
    store = MetricStore(tmp_path / "test.db")
    snap = make_snapshot()
    store.save_snapshot(snap)
    latest = store.latest_snapshots()
    assert len(latest) == 1
    assert latest[0].identity.hostname == "test01"
    history = store.history("test01", "cpu_pct", days=1)
    assert history.values() == [25.0]
    store.close()


def test_json_report(tmp_path: Path) -> None:
    path = JsonReporter().render(_context(), tmp_path)
    data = json.loads(path.read_text())
    assert data["summary"]["total_servers"] == 2
    assert len(data["servers"]) == 2


def test_csv_report(tmp_path: Path) -> None:
    path = CsvReporter().render(_context(), tmp_path)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("hostname,")


def test_markdown_report(tmp_path: Path) -> None:
    path = MarkdownReporter().render(_context(), tmp_path)
    text = path.read_text()
    assert "Executive Summary" in text
    assert "ghost01" in text


def test_html_report(tmp_path: Path) -> None:
    path = HtmlReporter().render(_context(), tmp_path)
    assert "<html" in path.read_text()


def test_dashboard(tmp_path: Path) -> None:
    store = MetricStore(tmp_path / "dash.db")
    ctx = _context()
    out = DashboardBuilder(store).build(ctx, tmp_path / "dashboard.html")
    html = out.read_text()
    assert "ServerScope Dashboard" in html
    assert "ghost01" in html
    store.close()


def test_example_config_loads() -> None:
    cfg = load_config(Path(__file__).parent.parent / "config" / "config.example.yaml")
    assert cfg.concurrency.max_parallel == 50
    assert cfg.credential_for(cfg.targets[0]).kind == "ssh"
