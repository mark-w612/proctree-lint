"""Command-line entry point: `proctree-lint [FILE]`.

Both `open()` file handles and sys.stdin are line-iterable in a way
that pulls one line at a time from the OS, so a multi-gigabyte tree
dump never has to fit in memory at once -- see parser.py for where
that guarantee actually lives.
"""

import argparse
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
    args = parser.parse_args(argv)

    try:
        if args.path:
            with open(args.path, "r", encoding="utf-8") as handle:
                findings = lint(handle)
        else:
            findings = lint(sys.stdin)
    except ParseError as exc:
        print(f"{args.path or '<stdin>'}: {exc}", file=sys.stderr)
        return 2

    for finding in sorted(findings, key=lambda f: f.line_no):
        print(str(finding))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
