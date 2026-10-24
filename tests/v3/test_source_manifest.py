import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = "daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08"


class SourceManifestModeTests(unittest.TestCase):
    def test_pinned_baseline_verification_reports_dev_delta_separately(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/check_source_manifest.py"), "--baseline-ref", BASELINE],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("138 source files SHA-256 verified at baseline", result.stdout)
        self.assertIn("baseline manifest does not cover these changes", result.stdout)


if __name__ == "__main__":
    unittest.main()
