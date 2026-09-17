import tempfile
import unittest
from pathlib import Path

from proctreelint.config import ConfigError, load_name_lists


def write_config(text: str) -> str:
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    handle.write(text)
    handle.close()
    return handle.name


class LoadNameListsTest(unittest.TestCase):
    def test_reads_both_lists(self):
        path = write_config('{"shell_names": ["fish"], "daemon_names": ["redis-server"]}')
        try:
            shells, daemons = load_name_lists(path)
        finally:
            Path(path).unlink()
        self.assertEqual(shells, {"fish"})
        self.assertEqual(daemons, {"redis-server"})

    def test_missing_keys_default_to_empty(self):
        path = write_config("{}")
        try:
            shells, daemons = load_name_lists(path)
        finally:
            Path(path).unlink()
        self.assertEqual(shells, set())
        self.assertEqual(daemons, set())

    def test_missing_file_raises_config_error(self):
        with self.assertRaises(ConfigError):
            load_name_lists("/no/such/file.json")

    def test_invalid_json_raises_config_error(self):
        path = write_config("not json")
        try:
            with self.assertRaises(ConfigError):
                load_name_lists(path)
        finally:
            Path(path).unlink()

    def test_non_object_top_level_raises_config_error(self):
        path = write_config("[1, 2, 3]")
        try:
            with self.assertRaises(ConfigError):
                load_name_lists(path)
        finally:
            Path(path).unlink()

    def test_non_string_list_item_raises_config_error(self):
        path = write_config('{"shell_names": ["fish", 5]}')
        try:
            with self.assertRaises(ConfigError):
                load_name_lists(path)
        finally:
            Path(path).unlink()

    def test_unknown_key_raises_config_error(self):
        path = write_config('{"shells": ["fish"]}')
        try:
            with self.assertRaises(ConfigError):
                load_name_lists(path)
        finally:
            Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
