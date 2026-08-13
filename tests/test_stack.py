from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mado.config import Config
from mado.scanners.registry import detect_stack, detect_stack_for_path, select_scanners


class StackDetectionTests(unittest.TestCase):
    def test_detect_stack_by_indicator_files(self) -> None:
        self.assertIn("python", detect_stack(["requirements.txt", "src/app.py"]))
        self.assertIn("node", detect_stack(["package.json"]))
        self.assertIn("go", detect_stack(["go.mod"]))
        self.assertEqual(detect_stack(["src/app.py"]), set())

    def test_detect_stack_for_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("flask\n", encoding="utf-8")
            (root / "package.json").write_text("{}", encoding="utf-8")
            stacks = detect_stack_for_path(str(root))
            self.assertIn("python", stacks)
            self.assertIn("node", stacks)

    def test_select_scanners_returns_installed_only(self) -> None:
        stacks = {"python"}
        selected = select_scanners(".", stacks)
        names = {scanner.name for scanner in selected}
        self.assertIn("semgrep", names)

    def test_select_scanners_propagates_excludes(self) -> None:
        config = Config(ignore_paths=[".venv", "vendor/"])
        selected = select_scanners(".", {"python"}, config)
        for scanner in selected:
            if scanner.name in {"semgrep", "bandit"}:
                self.assertIn(".venv", scanner.exclude)
                self.assertIn("vendor", scanner.exclude)

    def test_excludes_skip_unsafe_patterns(self) -> None:
        config = Config(ignore_paths=["/etc", "~/code", "../outside", "tests/"])
        selected = select_scanners(".", {"python"}, config)
        for scanner in selected:
            if scanner.name in {"semgrep", "bandit"}:
                self.assertEqual(scanner.exclude, ("tests",))


if __name__ == "__main__":
    unittest.main()
