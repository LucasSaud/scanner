#!/usr/bin/env python3
"""CLI mode — scan projects without GUI (ideal for CI/CD)."""

import argparse
import json as json_mod
import sys
from pathlib import Path

from security_scanner.scanners import ScannerManager
from security_scanner.models import SEVERITY_SORT_PRIORITY

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _color_for_severity(severity: str) -> str:
    return {"CRITICAL": RED + BOLD, "HIGH": RED, "MEDIUM": YELLOW}.get(severity, "")


def print_report(result, output_json: bool):
    if not result.findings:
        print(f"\n{GREEN}{BOLD}[OK] No threats detected.{RESET}")
        return
    sorted_f = sorted(result.findings, key=lambda f: SEVERITY_SORT_PRIORITY.get(f.severity, 9))
    print(f"\n{BOLD}{'='*60}")
    print(f"  SECURITY REPORT — {len(result.findings)} finding(s)")
    if result.correlations:
        print(f"  Correlations: {len(result.correlations)}")
    print(f"{'='*60}{RESET}\n")
    for i, f in enumerate(sorted_f, 1):
        color = _color_for_severity(f.severity)
        print(f"{color}[{f.severity}] #{i} — {f.description}{RESET}")
        print(f"  File : {f.file_path}")
        if f.detected_terms:
            print(f"  Terms: {f.detected_terms}")
        if f.evidence:
            print(f"  Evidence: {f.evidence[:200]}\n")
    if result.correlations:
        print(f"\n{BOLD}{'='*60}")
        print(f"  CORRELATIONS ({len(result.correlations)})")
        print(f"{'='*60}{RESET}\n")
        for i, ev in enumerate(result.correlations, 1):
            color = _color_for_severity(ev.get("severity", "MEDIUM"))
            print(f"{color}[{ev.get('severity','')}] Corr #{i} — {ev.get('name','')}{RESET}")
            print(f"  Rule : {ev.get('rule_id','')}")
            print(f"  Desc : {ev.get('description','')[:200]}\n")


def main():
    parser = argparse.ArgumentParser(
        description="VSCode Security Scanner — CLI mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  cli.py scan --path .\n"
            "  cli.py scan --path /path/to/project --json report.json\n"
            "  cli.py scan --no-global\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument(
        "--path", default=".", help="Project directory to scan (default: current dir)"
    )
    scan_parser.add_argument(
        "--json", help="Export findings to JSON file at this path"
    )
    scan_parser.add_argument(
        "--no-global", action="store_true", help="Skip ~/.vscode/ global scan"
    )

    args = parser.parse_args()

    if args.command == "scan":
        manager = ScannerManager()
        result = manager.scan_path(
            Path(args.path),
            include_global=not args.no_global,
        )
        print_report(result, bool(args.json))
        if args.json:
            output = {"scan": result.to_dict()}
            Path(args.json).write_text(
                json_mod.dumps(output, indent=2, default=str),
                encoding="utf-8",
            )
            print(f"\nReport saved: {args.json}")


if __name__ == "__main__":
    main()
