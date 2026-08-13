"""ServerScope CLI: collect, analyze, report, dashboard, or full run."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from serverscope.analyzer.engine import AnalysisEngine
from serverscope.collector.orchestrator import Orchestrator
from serverscope.core.config import AppConfig, load_config
from serverscope.core.logging import setup_logging
from serverscope.core.models import AnalysisResult, ServerSnapshot
from serverscope.core.registry import reporter_registry
from serverscope.core.storage import MetricStore
from serverscope.dashboard.builder import DashboardBuilder
from serverscope.report.base import ReportContext

log = logging.getLogger("serverscope")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="serverscope",
                                description="Infrastructure discovery and utilization analysis")
    p.add_argument("-c", "--config", default="config/config.yaml", help="path to YAML config")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="collect metrics from all targets")
    collect.add_argument("--target", action="append", help="limit to target name(s)")

    sub.add_parser("analyze", help="score latest snapshots and print results")

    report = sub.add_parser("report", help="generate reports from latest data")
    report.add_argument("--format", action="append", help="json/csv/markdown/html/excel/pdf")

    sub.add_parser("dashboard", help="build the interactive HTML dashboard")

    run = sub.add_parser("run", help="collect + analyze + report + dashboard")
    run.add_argument("--target", action="append")
    return p


def _analyze(config: AppConfig, store: MetricStore,
             snapshots: list[ServerSnapshot]) -> list[AnalysisResult]:
    return AnalysisEngine(config, store).analyze(snapshots)


def _print_results(results: list[AnalysisResult]) -> None:
    for r in results:
        print(f"\nServer: {r.hostname}  [{r.platform.value}]")
        print(f"  Classification:          {r.classification.value}")
        print(f"  Health Score:            {r.scores.health}/100")
        print(f"  Idle Probability:        {r.scores.idle_probability}%")
        print(f"  Abandonment Probability: {r.scores.abandonment_probability}%")
        print(f"  Grades: perf={r.performance_grade} sec={r.security_grade} "
              f"avail={r.availability_grade}")
        if r.reasons:
            print("  Reasons:")
            for reason in r.reasons:
                print(f"    - {reason}")
        for a in r.anomalies:
            print(f"  [{a.severity.value}] {a.kind}: {a.description}")
        print(f"  Recommendation: {r.recommendation}")


def _reports(config: AppConfig, context: ReportContext, formats: list[str]) -> None:
    out = Path(config.report.output_dir)
    for fmt in formats:
        try:
            reporter = reporter_registry.get(fmt)()
            path = reporter.render(context, out)
            log.info("wrote %s report: %s", fmt, path)
        except (KeyError, RuntimeError) as exc:
            log.error("report %s skipped: %s", fmt, exc)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    setup_logging(args.verbose)
    config = load_config(args.config)
    store = MetricStore(config.storage.path)
    try:
        return _dispatch(args, config, store)
    finally:
        store.close()


def _dispatch(args: argparse.Namespace, config: AppConfig, store: MetricStore) -> int:
    if args.command in ("collect", "run"):
        only = set(args.target) if getattr(args, "target", None) else None
        run = asyncio.run(Orchestrator(config, store).run(only))
        snapshots = run.snapshots
        if run.failures:
            log.warning("failed hosts: %s", ", ".join(sorted(run.failures)))
        if args.command == "collect":
            return 0 if snapshots else 1
    else:
        snapshots = store.latest_snapshots()
        if not snapshots:
            log.error("no snapshots in %s — run 'serverscope collect' first",
                      config.storage.path)
            return 1

    results = _analyze(config, store, snapshots)
    context = ReportContext.build(snapshots, results)

    match args.command:
        case "analyze":
            _print_results(results)
        case "report":
            _reports(config, context, args.format or config.report.formats)
        case "dashboard":
            path = DashboardBuilder(store).build(context, config.dashboard.output)
            log.info("dashboard: %s", path)
        case "run":
            _print_results(results)
            _reports(config, context, config.report.formats)
            path = DashboardBuilder(store).build(context, config.dashboard.output)
            log.info("dashboard: %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
