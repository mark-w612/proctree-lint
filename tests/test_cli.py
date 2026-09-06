import contextlib
import io
import json
import unittest

from proctreelint.cli import lint, main

TREE = [
    "1:systemd\n",
    "  142:sshd\n",
    "    891:curl\n",
    "  142:cron\n",
]


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = main(argv)
    return status, out.getvalue(), err.getvalue()


def run_with_stdin(lines, argv=()):
    import proctreelint.cli as cli_module

    original_stdin = cli_module.sys.stdin
    cli_module.sys.stdin = io.StringIO("".join(lines))
    try:
        return run_main(list(argv))
    finally:
        cli_module.sys.stdin = original_stdin


class LintTest(unittest.TestCase):
    def test_lint_returns_findings_across_all_rules(self):
        findings = lint(TREE)
        self.assertEqual([f.code for f in findings], ["dup-pid"])
        self.assertEqual(findings[0].line_no, 4)


class MainTextOutputTest(unittest.TestCase):
    def test_clean_input_exits_zero(self):
        status, out, err = run_with_stdin(["1:systemd\n", "  142:sshd\n"])
        self.assertEqual(status, 0)
        self.assertEqual(out, "")

    def test_findings_print_one_line_each(self):
        status, out, err = run_with_stdin(TREE)
        self.assertEqual(status, 1)
        self.assertIn("4: error dup-pid: pid 142 already seen on line 2", out)

    def test_parse_error_exits_two(self):
        status, out, err = run_with_stdin(["1 systemd\n"])
        self.assertEqual(status, 2)
        self.assertIn("line 1", err)


class MainJsonOutputTest(unittest.TestCase):
    def test_findings_are_a_json_array(self):
        status, out, err = run_with_stdin(TREE, ["--format", "json"])
        self.assertEqual(status, 1)
        payload = json.loads(out)
        self.assertEqual(len(payload), 1)
        self.assertEqual(
            payload[0],
            {
                "line": 4,
                "code": "dup-pid",
                "severity": "error",
                "message": "pid 142 already seen on line 2",
            },
        )

    def test_no_findings_is_an_empty_json_array(self):
        status, out, err = run_with_stdin(["1:systemd\n"], ["--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out), [])

    def test_parse_error_is_json_on_stderr(self):
        status, out, err = run_with_stdin(["1 systemd\n"], ["--format", "json"])
        self.assertEqual(status, 2)
        self.assertEqual(out, "")
        payload = json.loads(err)
        self.assertEqual(payload["line"], 1)


if __name__ == "__main__":
    unittest.main()
