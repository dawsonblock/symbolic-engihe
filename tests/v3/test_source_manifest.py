import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = "daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08"


def _baseline_available():
    try:
        subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", f"{BASELINE}^{{commit}}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


class SourceManifestModeTests(unittest.TestCase):
    def test_pinned_baseline_verification_reports_dev_delta_separately(self):
        if not _baseline_available():
            self.skipTest(
                "pinned Git baseline objects are unavailable in this source "
                "distribution; baseline verification requires the pinned checkout"
            )
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/check_source_manifest.py"), "--baseline-ref", BASELINE],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("138 source files SHA-256 verified at baseline", result.stdout)
        self.assertIn("baseline manifest does not cover these changes", result.stdout)

    def test_release_manifest_covers_worktree(self):
        """The regenerated release manifest must cover the working tree."""
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/check_source_manifest.py")],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("SHA-256 verified in the current working tree", result.stdout)

    def test_unmanifested_files_fail_worktree_verification(self):
        """A file absent from the manifest must still be detected."""
        scratch = ROOT / "unmanifested_probe.txt"
        scratch.write_text("probe\n")
        try:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/check_source_manifest.py")],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        finally:
            scratch.unlink()
        self.assertEqual(1, result.returncode)
        self.assertIn("working-tree inventory mismatch", result.stderr)
        self.assertIn("unmanifested_probe.txt", result.stderr)


if __name__ == "__main__":
    unittest.main()
