"""Loading user overrides for the daemon/shell name lists rules.py ships with.

Kept separate from rules.py so the rule definitions stay readable and
the file-format concerns (JSON, error messages) don't leak into them.
"""

import json
from pathlib import Path


class ConfigError(Exception):
    pass


def load_name_lists(path: str) -> tuple[set[str], set[str]]:
    """Read a JSON config file and return (extra_shell_names, extra_daemon_names).

    The file is additive, not a replacement: entries here are added to
    the built-in SHELL_NAMES/DAEMON_NAMES sets in rules.py, so a config
    can flag one extra in-house daemon without having to re-list nginx,
    sshd, and everything else that's already covered by default.

    Expected shape:

        {
          "shell_names": ["fish", "ksh"],
          "daemon_names": ["redis-server", "mongod"]
        }

    Either key may be omitted.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config file {path!r}: {exc.strerror}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON: {exc.msg} (line {exc.lineno})") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level JSON value must be an object")

    known_keys = {"shell_names", "daemon_names"}
    unknown = set(data) - known_keys
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")

    return (
        _string_set(data, "shell_names", path),
        _string_set(data, "daemon_names", path),
    )


def _string_set(data: dict, key: str, path: str) -> set:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{path}: {key!r} must be a list of strings")
    return set(value)
