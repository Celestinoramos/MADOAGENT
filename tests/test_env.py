from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mado.env import find_env_file, load_project_env, parse_env_file


class EnvTests(unittest.TestCase):
    def test_parse_env_file_basic(self) -> None:
        values = parse_env_file("# comment\nANTHROPIC_API_KEY=sk-ant-test\nEMPTY=\n\nQUOTED='v a l'\nDOUBLE=\"x y\"\n")
        self.assertEqual(values["ANTHROPIC_API_KEY"], "sk-ant-test")
        self.assertEqual(values["QUOTED"], "v a l")
        self.assertEqual(values["DOUBLE"], "x y")

    def test_parse_env_file_export_and_inline(self) -> None:
        values = parse_env_file("export FOO=bar\nFOO2 = baz\nNO_VALUE\n")
        self.assertEqual(values["FOO"], "bar")
        self.assertEqual(values["FOO2"], "baz")
        self.assertNotIn("NO_VALUE", values)

    def test_load_project_env_sets_missing_vars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-local\n", encoding="utf-8")
            os.environ.pop("ANTHROPIC_API_KEY", None)
            try:
                load_project_env(root)
                self.assertEqual(os.environ["ANTHROPIC_API_KEY"], "sk-ant-local")
            finally:
                os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_real_env_var_wins_over_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-file\n", encoding="utf-8")
            os.environ["ANTHROPIC_API_KEY"] = "sk-ant-real"
            try:
                load_project_env(root)
                self.assertEqual(os.environ["ANTHROPIC_API_KEY"], "sk-ant-real")
            finally:
                os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_find_env_file_walks_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("A=1\n", encoding="utf-8")
            nested = root / "a" / "b"
            nested.mkdir(parents=True)
            self.assertEqual(find_env_file(nested), root / ".env")

    @patch("mado.env.find_env_file", return_value=None)
    def test_load_project_env_without_file_is_noop(self, _mock_find: object) -> None:
        load_project_env(".")
        self.assertNotIn("MADO_TEST_UNSET", os.environ)


if __name__ == "__main__":
    unittest.main()
