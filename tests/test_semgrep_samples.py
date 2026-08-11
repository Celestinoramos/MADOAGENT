from __future__ import annotations

import re
import unittest
from pathlib import Path


class SemgrepSamplesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]
        self.rules_file = self.repo_root / "src" / "mado" / "scanners" / "rules" / "semgrep.yml"
        self.samples_dir = self.repo_root / "tests" / "samples"

    def _extract_pattern_regexes(self) -> dict[str, str]:
        text = self.rules_file.read_text(encoding="utf-8")
        patterns: dict[str, str] = {}
        current_id = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("- id:"):
                current_id = line.split("- id:", 1)[1].strip()
            elif line.startswith("pattern-regex:") and current_id:
                # capture rest of line after colon, strip quotes
                patt = line.split("pattern-regex:", 1)[1].strip()
                patt = patt.strip("'\"")
                patterns[current_id] = patt
                current_id = None
        return patterns

    def test_each_rule_matches_at_least_one_sample(self) -> None:
        patterns = self._extract_pattern_regexes()
        sample_files = list(self.samples_dir.glob("*.py"))
        self.assertTrue(sample_files, "No sample files found in tests/samples")

        for rule_id, pattern in patterns.items():
            compiled = re.compile(pattern)
            matched = False
            for sample in sample_files:
                content = sample.read_text(encoding="utf-8")
                if compiled.search(content):
                    matched = True
                    break
            # only assert for rules that are intended to be matched by samples
            self.assertTrue(matched, f"Rule {rule_id} did not match any sample files (regex: {pattern})")


if __name__ == "__main__":
    unittest.main()
