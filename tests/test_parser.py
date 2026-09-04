import unittest

from proctreelint.parser import ParseError, parse_lines


class ParseLinesTest(unittest.TestCase):
    def test_single_root(self):
        nodes = list(parse_lines(["1:systemd\n"]))
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual((node.line_no, node.depth, node.pid, node.name), (1, 0, 1, "systemd"))
        self.assertIsNone(node.parent)

    def test_nested_tree_links_parents(self):
        lines = [
            "1:systemd\n",
            "  142:sshd\n",
            "    891:bash\n",
            "  205:cron\n",
        ]
        nodes = list(parse_lines(lines))
        by_pid = {node.pid: node for node in nodes}
        self.assertIsNone(by_pid[1].parent)
        self.assertIs(by_pid[142].parent, by_pid[1])
        self.assertIs(by_pid[891].parent, by_pid[142])
        # 205 dedents back to depth 1, so its parent is 1, not 142.
        self.assertIs(by_pid[205].parent, by_pid[1])

    def test_blank_lines_are_skipped(self):
        lines = ["1:systemd\n", "\n", "  142:sshd\n", "   \n"]
        nodes = list(parse_lines(lines))
        self.assertEqual([node.pid for node in nodes], [1, 142])
        # Blank lines don't consume a depth level or break parent linkage.
        self.assertIs(nodes[1].parent, nodes[0])

    def test_name_is_stripped(self):
        nodes = list(parse_lines(["1:  systemd  \n"]))
        self.assertEqual(nodes[0].name, "systemd")

    def test_odd_indent_raises(self):
        with self.assertRaises(ParseError) as ctx:
            list(parse_lines(["1:systemd\n", "   142:sshd\n"]))
        self.assertEqual(ctx.exception.line_no, 2)

    def test_skipped_depth_raises(self):
        # Depth 2 with nothing at depth 1 to attach to.
        with self.assertRaises(ParseError) as ctx:
            list(parse_lines(["1:systemd\n", "    142:sshd\n"]))
        self.assertEqual(ctx.exception.line_no, 2)

    def test_missing_colon_raises(self):
        with self.assertRaises(ParseError) as ctx:
            list(parse_lines(["1 systemd\n"]))
        self.assertEqual(ctx.exception.line_no, 1)

    def test_non_integer_pid_raises(self):
        with self.assertRaises(ParseError) as ctx:
            list(parse_lines(["abc:systemd\n"]))
        self.assertEqual(ctx.exception.line_no, 1)

    def test_sibling_after_deep_nesting(self):
        lines = [
            "1:systemd\n",
            "  142:sshd\n",
            "    891:bash\n",
            "      902:curl\n",
            "  205:cron\n",
        ]
        nodes = list(parse_lines(lines))
        depths = [node.depth for node in nodes]
        self.assertEqual(depths, [0, 1, 2, 3, 1])


if __name__ == "__main__":
    unittest.main()
