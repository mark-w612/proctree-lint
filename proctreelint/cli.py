"""Command-line entry point: `proctree-lint [FILE]`.

Both `open()` file handles and sys.stdin are line-iterable in a way
that pulls one line at a time from the OS, so a multi-gigabyte tree
dump never has to fit in memory at once -- see parser.py for where
that guarantee actually lives.
"""

import argparse
import json
import sys
from typing import Iterable

from .parser import ParseError, parse_lines
from .rules import Finding, default_rules


def lint(lines: Iterable[str]) -> list[Finding]:
    rules = default_rules()
    findings: list[Finding] = []
    for node in parse_lines(lines):
        for rule in rules:
            findings.extend(rule.on_node(node))
    return findings


def _print_text(findings: list[Finding]) -> None:
    for finding in findings:
        print(str(finding))


def _print_json(findings: list[Finding]) -> None:
    payload = [
        {
            "line": finding.line_no,
            "code": finding.code,
            "severity": finding.severity,
            "message": finding.message,
        }
        for finding in findings
    ]
    print(json.dumps(payload, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="proctree-lint",
        description="Lint an indented process-tree listing for suspicious or malformed entries.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="path to a process tree file; reads from stdin if omitted",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args(argv)

    try:
        if args.path:
            with open(args.path, "r", encoding="utf-8") as handle:
                findings = lint(handle)
        else:
            findings = lint(sys.stdin)
    except ParseError as exc:
        if args.format == "json":
            print(json.dumps({"error": exc.message, "line": exc.line_no}), file=sys.stderr)
        else:
            print(f"{args.path or '<stdin>'}: {exc}", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: f.line_no)

    if args.format == "json":
        _print_json(findings)
    else:
        _print_text(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
