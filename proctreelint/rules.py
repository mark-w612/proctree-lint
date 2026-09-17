"""Lint rules for process trees.

Each rule is a small stateful object with an `on_node(node)` method
called once per ProcessNode as the tree streams past. Rules should
only keep the minimum state they need (a set of pids, a threshold
counter) rather than holding onto ProcessNode objects themselves --
that's what keeps the overall lint pass streaming instead of turning
into "parse everything into a tree, then inspect it".
"""

from dataclasses import dataclass
from typing import Iterator

from .parser import ProcessNode

# Interpreters and shells that are unremarkable when launched from a
# login shell or terminal, but worth a second look when launched
# directly by a long-running network-facing daemon.
SHELL_NAMES = {"sh", "bash", "zsh", "dash", "powershell", "cmd"}
DAEMON_NAMES = {"nginx", "apache2", "httpd", "sshd", "mysqld", "postgres"}


@dataclass
class Finding:
    line_no: int
    code: str
    severity: str  # "error" or "warning"
    message: str

    def __str__(self) -> str:
        return f"{self.line_no}: {self.severity} {self.code}: {self.message}"


class DuplicatePidRule:
    """A pid should only appear once in a single tree snapshot."""

    code = "dup-pid"

    def __init__(self) -> None:
        self._seen: dict[int, int] = {}

    def on_node(self, node: ProcessNode) -> Iterator[Finding]:
        first_line = self._seen.get(node.pid)
        if first_line is not None:
            yield Finding(
                node.line_no,
                self.code,
                "error",
                f"pid {node.pid} already seen on line {first_line}",
            )
        else:
            self._seen[node.pid] = node.line_no


class EmptyNameRule:
    """A process with no name is either a parse artifact or truncated data."""

    code = "empty-name"

    def on_node(self, node: ProcessNode) -> Iterator[Finding]:
        if not node.name:
            yield Finding(node.line_no, self.code, "error", f"pid {node.pid} has an empty name")


class DaemonSpawnsShellRule:
    """Flag a shell launched directly by a network-facing daemon.

    This is a heuristic, not a verdict -- plenty of daemons legitimately
    shell out. It exists to draw attention during review, not to block.
    """

    code = "daemon-spawns-shell"

    def __init__(self, shell_names: set = SHELL_NAMES, daemon_names: set = DAEMON_NAMES) -> None:
        self.shell_names = shell_names
        self.daemon_names = daemon_names

    def on_node(self, node: ProcessNode) -> Iterator[Finding]:
        parent = node.parent
        if parent is not None and node.name in self.shell_names and parent.name in self.daemon_names:
            yield Finding(
                node.line_no,
                self.code,
                "warning",
                f"{parent.name} (pid {parent.pid}) spawned shell {node.name} (pid {node.pid})",
            )


class DeepRepeatChainRule:
    """Flag a long unbroken chain of processes with the same name.

    A handful of identical names in a row is normal (re-exec wrappers,
    setuid helpers). A long unbroken run is more often a respawn loop
    than deliberate nesting, so it's worth a warning past `threshold`.
    """

    code = "deep-repeat"

    def __init__(self, threshold: int = 6) -> None:
        self.threshold = threshold

    def on_node(self, node: ProcessNode) -> Iterator[Finding]:
        run = 1
        ancestor = node.parent
        while ancestor is not None and ancestor.name == node.name:
            run += 1
            ancestor = ancestor.parent
        # Only fire the moment the run crosses the threshold, so a
        # 20-deep chain reports once instead of fourteen times.
        if run == self.threshold:
            yield Finding(
                node.line_no,
                self.code,
                "warning",
                f"{node.name} repeats {run} times in a row up to pid {node.pid}",
            )


def default_rules(extra_shell_names: set = frozenset(), extra_daemon_names: set = frozenset()) -> list:
    return [
        DuplicatePidRule(),
        EmptyNameRule(),
        DaemonSpawnsShellRule(SHELL_NAMES | extra_shell_names, DAEMON_NAMES | extra_daemon_names),
        DeepRepeatChainRule(),
    ]
