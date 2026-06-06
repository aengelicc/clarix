"""Command-line interface for Clarix.

Subcommands:
- scan    Run static analysis on a local path. Output text/json/sarif.
- rules   List all built-in rules (or filter by scanner).
- version Print the Clarix version and exit.

Exit codes:
  0  No findings at or above the severity threshold
  1  Findings at or above the severity threshold were found
  2  Usage / configuration error
  3  Internal error during scan
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from clarix_cli import __version__


# Exit codes — kept stable for CI consumers.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_SCAN_ERROR = 3

# Severity ordering for threshold comparison.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clarix",
        description="Pre-deployment security analysis for your codebase.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---------------------------------------------------------------
    scan = sub.add_parser(
        "scan",
        help="Scan a local path and report findings.",
    )
    scan.add_argument("path", help="Path to a local directory to scan.")
    scan.add_argument(
        "--format", "-f",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format (default: text).",
    )
    scan.add_argument(
        "--severity-threshold", "-t",
        choices=sorted(SEVERITY_RANK.keys()),
        default="low",
        help="Minimum severity to include in the output and to fail on. Default: low.",
    )
    scan.add_argument(
        "--fail-on",
        choices=sorted(SEVERITY_RANK.keys()),
        default=None,
        help="Severity at which the CLI should exit non-zero. Defaults to --severity-threshold.",
    )
    scan.add_argument(
        "--output", "-o",
        default=None,
        help="Write output to this file instead of stdout.",
    )
    scan.add_argument(
        "--max-files", type=int, default=None,
        help="Override MAX_FILES (default uses server config).",
    )
    scan.add_argument(
        "--max-file-size-kb", type=int, default=None,
        help="Override MAX_FILE_SIZE_KB.",
    )
    scan.add_argument(
        "--include-hidden", action="store_true",
        help="Include hidden files and dotfile directories (default: skip).",
    )
    scan.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-finding text output; useful with --format json/sarif.",
    )
    scan.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour in text output.",
    )

    # --- rules --------------------------------------------------------------
    rules = sub.add_parser("rules", help="List built-in rules.")
    rules.add_argument(
        "--scanner", "-s",
        choices=("security", "hipaa", "pci", "gdpr", "soc2", "owasp", "cis"),
        default=None,
        help="Filter by scanner.",
    )
    rules.add_argument(
        "--format", "-f", choices=("text", "json"), default="text",
        help="Output format (default: text).",
    )

    # --- version ------------------------------------------------------------
    sub.add_parser("version", help="Print Clarix version and exit.")

    return parser


def _all_issues(report) -> list:
    issues = list(getattr(report, "security_findings", []) or [])
    for fa in (getattr(report, "file_analyses", []) or []):
        issues.extend(fa.issues or [])
    issues.extend(getattr(report, "project_level_issues", []) or [])
    return issues


def _filter_issues(issues, min_severity: str) -> list:
    threshold = SEVERITY_RANK[min_severity]
    return [i for i in issues if SEVERITY_RANK.get(i.severity.value, 0) >= threshold]


def _format_text(report, issues, *, use_color: bool) -> str:
    """Human-readable report: one block per finding plus a summary footer."""
    c_red = "\x1b[31m" if use_color else ""
    c_yellow = "\x1b[33m" if use_color else ""
    c_green = "\x1b[32m" if use_color else ""
    c_bold = "\x1b[1m" if use_color else ""
    c_dim = "\x1b[2m" if use_color else ""
    c_reset = "\x1b[0m" if use_color else ""

    sev_color = {
        "critical": c_red, "high": c_red,
        "medium": c_yellow, "low": c_yellow, "info": c_dim,
    }

    lines: List[str] = []
    lines.append(f"{c_bold}Clarix scan: {report.repo_name}{c_reset}")
    lines.append(f"{c_dim}files analyzed: {(report.metadata or {}).get('total_files_analyzed', 0)}  "
                 f"issues shown: {len(issues)}{c_reset}")
    lines.append("")

    if not issues:
        lines.append(f"{c_green}No findings at or above the selected threshold.{c_reset}")
        return "\n".join(lines)

    for issue in issues:
        sev = issue.severity.value
        loc = f"{issue.file}" + (f":{issue.line}" if issue.line else "")
        lines.append(f"{sev_color.get(sev, '')}{sev.upper():>8s}{c_reset}  {c_bold}{issue.description}{c_reset}")
        lines.append(f"  {c_dim}at {loc}  [{issue.source}]{c_reset}")
        if getattr(issue, "rule_id", None):
            lines.append(f"  {c_dim}rule: {issue.rule_id}{c_reset}")
        if getattr(issue, "compliance_ref", None):
            lines.append(f"  {c_dim}compliance: {issue.compliance_ref}{c_reset}")
        if issue.recommendation:
            lines.append(f"  fix: {issue.recommendation}")
        if getattr(issue, "code_snippet", None):
            lines.append(f"  {c_dim}```\n  {issue.code_snippet}\n  ```{c_reset}")
        lines.append("")

    return "\n".join(lines)


def _format_json(report, issues) -> str:
    """Emit the same ProjectReport shape but with only the issues that passed the threshold."""
    keep_ids = {id(i) for i in issues}
    report_dict = report.model_dump(mode="json")
    report_dict["security_findings"] = [
        i.model_dump(mode="json") for i in (report.security_findings or []) if id(i) in keep_ids
    ]
    report_dict["file_analyses"] = [
        {**fa.model_dump(mode="json"),
         "issues": [i.model_dump(mode="json") for i in (fa.issues or []) if id(i) in keep_ids]}
        for fa in (report.file_analyses or [])
    ]
    report_dict["project_level_issues"] = [
        i.model_dump(mode="json") for i in (report.project_level_issues or []) if id(i) in keep_ids
    ]
    return json.dumps(report_dict, indent=2, ensure_ascii=False)


def _format_sarif(report, issues) -> str:
    from app.services.sarif import build_sarif
    # Build SARIF from a synthetic report containing only the filtered issues.
    # Easier: use the report but pre-filter by replacing the lists.
    report.security_findings = [i for i in issues if i in (report.security_findings or [])]
    report.file_analyses = [
        fa for fa in (report.file_analyses or [])
        if any(id(i) in {id(x) for x in issues} for i in (fa.issues or []))
    ]
    for fa in report.file_analyses:
        keep = {id(x) for x in issues}
        fa.issues = [i for i in (fa.issues or []) if id(i) in keep]
    report.project_level_issues = [
        i for i in issues if i in (report.project_level_issues or [])
    ]
    return json.dumps(build_sarif(report), ensure_ascii=False)


def _run_scan(args: argparse.Namespace) -> int:
    """Execute the `scan` subcommand. Returns the desired process exit code."""
    from app.core.config import settings  # local import — keep CLI importable without app init
    from app.services.analyzer import CodeAnalyzer
    from app.services.file_utils import get_repo_files

    path = Path(args.path).resolve()
    if not path.exists() or not path.is_dir():
        print(f"error: path does not exist or is not a directory: {path}", file=sys.stderr)
        return EXIT_USAGE

    max_files = args.max_files if args.max_files is not None else settings.max_files
    max_size = args.max_file_size_kb if args.max_file_size_kb is not None else settings.max_file_size_kb

    try:
        files = get_repo_files(
            str(path),
            max_file_size_kb=max_size,
            max_files=max_files,
            include_hidden=args.include_hidden,
        )
    except Exception as e:
        print(f"error: failed to enumerate files: {e}", file=sys.stderr)
        return EXIT_SCAN_ERROR

    if not files:
        print("error: no analyzable code files found in the path.", file=sys.stderr)
        return EXIT_SCAN_ERROR

    analyzer = CodeAnalyzer(llm_client=None)  # CLI is static-only by design
    try:
        report = analyzer.analyze_repo(
            repo_path=str(path),
            files=files,
            repo_name=path.name,
            source_type="local",
            mode="static",
        )
    except Exception as e:
        print(f"error: scan failed: {e}", file=sys.stderr)
        return EXIT_SCAN_ERROR

    issues = _filter_issues(_all_issues(report), args.severity_threshold)

    if args.format == "text":
        text = _format_text(report, issues, use_color=sys.stdout.isatty() and not args.no_color)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
    elif args.format == "json":
        text = _format_json(report, issues)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
    elif args.format == "sarif":
        text = _format_sarif(report, issues)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)

    fail_on = args.fail_on or args.severity_threshold
    fail_rank = SEVERITY_RANK[fail_on]
    has_failing = any(SEVERITY_RANK.get(i.severity.value, 0) >= fail_rank for i in issues)
    return EXIT_FINDINGS if has_failing else EXIT_OK


def _run_rules(args: argparse.Namespace) -> int:
    from app.services import rules_store
    rules = rules_store.get_all_rules()
    if args.scanner:
        rules = [r for r in rules if r.scanner == args.scanner]

    if args.format == "json":
        print(json.dumps([r.model_dump(mode="json") for r in rules], indent=2, ensure_ascii=False))
        return EXIT_OK

    if not rules:
        print(f"(no rules match scanner={args.scanner!r})")
        return EXIT_OK

    width = max(len(r.id) for r in rules)
    for r in rules:
        print(f"{r.id:<{width}}  {r.severity.value:<8}  {r.scanner:<6}  {r.name}")
    print(f"\n{len(rules)} rule(s).")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"clarix {__version__}")
        return EXIT_OK
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)

    parser.print_help(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
