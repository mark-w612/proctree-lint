"""Streaming parser for indentation-based process tree listings.

The format is deliberately simple: one process per line, two spaces
of indentation per level of the tree, "PID:NAME" as the content, e.g.

    1:systemd
      142:sshd
        891:bash

Lines are turned into ProcessNode objects one at a time and are not
kept around afterward. The only state that survives across lines is
`stack`, the list of currently-open ancestors, whose size tracks the
depth of the tree rather than its total size. That's what lets this
parser run against a file handle (or stdin) of any length without
buffering the input.
"""

from dataclasses import dataclass
from typing import Iterable, Iterator, Optional


class ParseError(Exception):
    def __init__(self, line_no: int, message: str):
        super().__init__(f"line {line_no}: {message}")
        self.line_no = line_no
        self.message = message


@dataclass
class ProcessNode:
    line_no: int
    depth: int
    pid: int
    name: str
    parent: Optional["ProcessNode"]


def _split_indent(raw_line: str) -> tuple[int, str]:
    stripped = raw_line.rstrip("\n")
    content = stripped.lstrip(" ")
    indent = len(stripped) - len(content)
    return indent, content


def parse_lines(lines: Iterable[str]) -> Iterator[ProcessNode]:
    """Parse an iterable of raw lines into ProcessNode objects.

    Pass a file object or sys.stdin rather than a list: those yield
    one line at a time from the OS, and this function never asks for
    more than the current line plus the ancestor stack.
    """
    stack: list[ProcessNode] = []

    for line_no, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue

        indent, content = _split_indent(raw_line)
        if indent % 2 != 0:
            raise ParseError(line_no, f"indent of {indent} spaces is not a multiple of 2")
        depth = indent // 2

        if ":" not in content:
            raise ParseError(line_no, f"expected 'PID:NAME', got {content!r}")
        pid_str, name = content.split(":", 1)
        try:
            pid = int(pid_str)
        except ValueError:
            raise ParseError(line_no, f"expected an integer pid, got {pid_str!r}")

        name = name.strip()

        while stack and stack[-1].depth >= depth:
            stack.pop()

        if depth > 0 and (not stack or stack[-1].depth != depth - 1):
            raise ParseError(
                line_no, f"process at depth {depth} has no parent at depth {depth - 1}"
            )

        parent = stack[-1] if stack else None
        node = ProcessNode(line_no=line_no, depth=depth, pid=pid, name=name, parent=parent)
        stack.append(node)
        yield node
