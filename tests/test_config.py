from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mado.config import Config, load_config, load_config_file, render_example_config


class ConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = Config()
        self.assertEqual(config.severity_threshold, "low")
        self.assertTrue(config.get_scanner_enabled("semgrep"))
        self.assertTrue(config.llm_enabled)
        self.assertTrue(config.zap_enabled)
        self.assertIn(".py", config.code_extensions)
        self.assertEqual(config.cache_ttl_days, 30)
        self.assertIn(".venv", config.ignore_paths)

    def test_from_dict_merges_over_defaults(self) -> None:
        config = Config.from_dict(
            {
                "severity_threshold": "high",
                "scanners": {"bandit": False},
                "ignore_paths": ["tests/"],
                "code_extensions": [".py", ".js"],
                "cache_ttl_days": None,
                "llm": {"enabled": False},
                "dast": {"enable_zap": False},
            }
        )
        self.assertEqual(config.severity_threshold, "high")
        self.assertFalse(config.get_scanner_enabled("bandit"))
        self.assertTrue(config.get_scanner_enabled("semgrep"))
        self.assertEqual(config.ignore_paths, ["tests/"])
        self.assertEqual(config.code_extensions, [".py", ".js"])
        self.assertIsNone(config.cache_ttl_days)
        self.assertFalse(config.llm_enabled)
        self.assertFalse(config.zap_enabled)

    def test_load_config_from_mado_yml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".mado.yml").write_text("severity_threshold: critical\n", encoding="utf-8")
            config = load_config(root)
            self.assertEqual(config.severity_threshold, "critical")
            self.assertEqual(config.source_path, str(root / ".mado.yml"))

    def test_load_config_file_explicit_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "custom.yml"
            path.write_text("severity_threshold: medium\n", encoding="utf-8")
            config = load_config_file(path)
            self.assertEqual(config.severity_threshold, "medium")

    def test_render_example_config_is_valid_yaml(self) -> None:
        import yaml

        parsed = yaml.safe_load(render_example_config())
        self.assertIn("severity_threshold", parsed)
        self.assertIn("scanners", parsed)


if __name__ == "__main__":
    unittest.main()
