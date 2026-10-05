"""Command-line entry point for maltriage."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze
from .models import FAILING_VERDICTS
from .parser import ReportError, parse
from .report import render_html, render_json, render_markdown, render_terminal


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="maltriage",
        description="Triage a CAPE/Cuckoo sandbox report.json into a verdict, "
        "MITRE ATT&CK mapping and extracted IOCs.",
    )
    p.add_argument("report", help="path to a sandbox report.json")
    p.add_argument(
        "-f",
        "--format",
        choices=["term", "md", "html", "json"],
        default="term",
        help="output format (default: term)",
    )
    p.add_argument("-o", "--output", help="write output to a file instead of stdout")
    p.add_argument(
        "--min-severity",
        type=int,
        default=0,
        metavar="N",
        help="only show signatures with severity >= N",
    )
    p.add_argument(
        "--iocs-only",
        action="store_true",
        help="with --format json, emit just the IOC block",
    )
    p.add_argument(
        "--no-fail",
        action="store_true",
        help="always exit 0 (do not signal HIGH/CRITICAL via exit code)",
    )
    p.add_argument("-V", "--version", action="version", version=f"maltriage {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = analyze(parse(args.report))
    except FileNotFoundError:
        print(f"error: file not found: {args.report}", file=sys.stderr)
        return 2
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "term" and not args.output:
        render_terminal(result, args.min_severity)
    else:
        if args.format == "md":
            text = render_markdown(result, args.min_severity)
        elif args.format == "html":
            text = render_html(result, args.min_severity)
        elif args.format == "json":
            text = render_json(result, iocs_only=args.iocs_only)
        else:  # term output redirected to a file -> fall back to markdown
            text = render_markdown(result, args.min_severity)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        else:
            print(text)

    if not args.no_fail and result.verdict in FAILING_VERDICTS:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
