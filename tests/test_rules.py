import unittest

from proctreelint.parser import ProcessNode
from proctreelint.rules import (
    DaemonSpawnsShellRule,
    DeepRepeatChainRule,
    DuplicatePidRule,
    EmptyNameRule,
    default_rules,
)


def make_node(pid, name, parent=None, line_no=None, depth=None):
    return ProcessNode(
        line_no=line_no if line_no is not None else pid,
        depth=depth if depth is not None else (0 if parent is None else parent.depth + 1),
        pid=pid,
        name=name,
        parent=parent,
    )


def make_chain(names):
    """Build a parent-linked chain of nodes, one per name, root first."""
    parent = None
    nodes = []
    for i, name in enumerate(names, start=1):
        node = make_node(pid=i, name=name, parent=parent)
        nodes.append(node)
        parent = node
    return nodes


class DuplicatePidRuleTest(unittest.TestCase):
    def test_first_sighting_is_clean(self):
        rule = DuplicatePidRule()
        findings = list(rule.on_node(make_node(1, "systemd")))
        self.assertEqual(findings, [])

    def test_second_sighting_flags_first_line(self):
        rule = DuplicatePidRule()
        first = make_node(343, "sh", line_no=9)
        second = make_node(343, "sh", line_no=10)
        list(rule.on_node(first))
        findings = list(rule.on_node(second))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_no, 10)
        self.assertEqual(findings[0].code, "dup-pid")
        self.assertIn("line 9", findings[0].message)


class EmptyNameRuleTest(unittest.TestCase):
    def test_empty_name_flagged(self):
        rule = EmptyNameRule()
        findings = list(rule.on_node(make_node(1, "")))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "empty-name")

    def test_non_empty_name_clean(self):
        rule = EmptyNameRule()
        self.assertEqual(list(rule.on_node(make_node(1, "systemd"))), [])


class DaemonSpawnsShellRuleTest(unittest.TestCase):
    def test_daemon_spawning_shell_flagged(self):
        rule = DaemonSpawnsShellRule()
        parent = make_node(1, "nginx")
        child = make_node(2, "bash", parent=parent)
        findings = list(rule.on_node(child))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "daemon-spawns-shell")

    def test_non_daemon_parent_is_clean(self):
        rule = DaemonSpawnsShellRule()
        parent = make_node(1, "systemd")
        child = make_node(2, "bash", parent=parent)
        self.assertEqual(list(rule.on_node(child)), [])

    def test_root_process_is_clean(self):
        rule = DaemonSpawnsShellRule()
        self.assertEqual(list(rule.on_node(make_node(1, "bash"))), [])

    def test_daemon_spawning_non_shell_is_clean(self):
        rule = DaemonSpawnsShellRule()
        parent = make_node(1, "nginx")
        child = make_node(2, "worker", parent=parent)
        self.assertEqual(list(rule.on_node(child)), [])


class DeepRepeatChainRuleTest(unittest.TestCase):
    def test_below_threshold_is_clean(self):
        rule = DeepRepeatChainRule(threshold=4)
        nodes = make_chain(["sh", "sh", "sh"])
        findings = [f for node in nodes for f in rule.on_node(node)]
        self.assertEqual(findings, [])

    def test_fires_once_at_threshold(self):
        rule = DeepRepeatChainRule(threshold=4)
        nodes = make_chain(["sh", "sh", "sh", "sh"])
        findings = [f for node in nodes for f in rule.on_node(node)]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_no, nodes[-1].line_no)
        self.assertEqual(findings[0].code, "deep-repeat")

    def test_does_not_refire_past_threshold(self):
        rule = DeepRepeatChainRule(threshold=4)
        nodes = make_chain(["sh", "sh", "sh", "sh", "sh", "sh"])
        findings = [f for node in nodes for f in rule.on_node(node)]
        # Only the node exactly at the threshold reports; longer runs
        # don't re-report at every subsequent depth.
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_no, nodes[3].line_no)

    def test_broken_chain_resets_run(self):
        rule = DeepRepeatChainRule(threshold=4)
        nodes = make_chain(["sh", "sh", "sh", "python", "sh", "sh", "sh"])
        findings = [f for node in nodes for f in rule.on_node(node)]
        self.assertEqual(findings, [])


class DefaultRulesTest(unittest.TestCase):
    def test_returns_one_instance_of_each_rule(self):
        rules = default_rules()
        rule_types = {type(rule) for rule in rules}
        self.assertEqual(
            rule_types,
            {DuplicatePidRule, EmptyNameRule, DaemonSpawnsShellRule, DeepRepeatChainRule},
        )
        self.assertEqual(len(rules), len(rule_types))


if __name__ == "__main__":
    unittest.main()
