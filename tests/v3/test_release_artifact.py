"""SIS3-101/102: fresh-extraction release verification + SQLite lifecycle."""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
import build_release  # noqa: E402
import verify_release  # noqa: E402


def _copy_subset(dst: Path, files: dict[str, bytes]):
    for rel, data in files.items():
        path = dst / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _copy_subset(self.root, {
            "src/pkg/a.py": b"print(1)\n",
            "src/pkg/b.py": b"X = 2\n",
            "docs/readme.md": b"hi\n",
        })

    def _build(self):
        files = build_release.inventory(self.root)
        (self.root / "RELEASE_SHA256.json").write_text(
            json.dumps({"schema": 1, "files": files}, sort_keys=True)
        )

    def test_fresh_tree_verifies(self):
        self._build()
        self.assertEqual(verify_release.verify_tree(self.root)["files"], 3)

    def test_tampered_file_fails_closed(self):
        self._build()
        (self.root / "src/pkg/a.py").write_bytes(b"print('pwned')\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_release.verify_tree(self.root)

    def test_extra_file_fails_closed(self):
        self._build()
        (self.root / "src/pkg/evil.py").write_bytes(b"import os\n")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify_release.verify_tree(self.root)

    def test_missing_file_fails_closed(self):
        self._build()
        (self.root / "src/pkg/b.py").unlink()
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify_release.verify_tree(self.root)

    def test_missing_manifest_fails(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            verify_release.verify_tree(self.root)

    def test_manifest_cannot_cover_itself(self):
        files = build_release.inventory(self.root)
        self.assertNotIn("RELEASE_SHA256.json", files)
        self.assertNotIn("SOURCE_SHA256.json", files)

    def test_skips_cache_and_db(self):
        _copy_subset(self.root, {
            "src/__pycache__/a.pyc": b"x",
            "data/state.db": b"x",
            "junk.log": b"x",
        })
        files = build_release.inventory(self.root)
        self.assertEqual(len(files), 3)


class SqliteLifecycleTests(unittest.TestCase):
    """Every SQLite owner supports close() and context management."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_registry_close_and_cm(self):
        from sis.registry import Registry
        reg = Registry(str(self.root / "r.db"))
        reg.close()
        with Registry(str(self.root / "r2.db")) as reg2:
            self.assertIs(reg2, reg2.__enter__())

    def test_family_eval_close_and_cm(self):
        from sis.family_eval import FamilyExperimentVault
        v = FamilyExperimentVault(str(self.root / "f.db"))
        v.close()
        with FamilyExperimentVault(str(self.root / "f2.db")):
            pass

    def test_skill_holdout_close_and_cm(self):
        from sis.skill_holdout import SkillHoldoutVault
        key = b"k" * 32
        v = SkillHoldoutVault(str(self.root / "s.db"), key=key)
        v.close()
        with SkillHoldoutVault(str(self.root / "s2.db"), key=key):
            pass

    def test_evaluator_vault_close_and_cm(self):
        from sis.sealed_eval import EvaluatorVault
        key = b"k" * 32
        v = EvaluatorVault(str(self.root / "e.db"), key=key)
        v.close()
        with EvaluatorVault(str(self.root / "e2.db"), key=key):
            pass

    def test_closed_connection_raises_on_use(self):
        import sqlite3
        from sis.family_eval import FamilyExperimentVault
        v = FamilyExperimentVault(str(self.root / "f3.db"))
        v.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            v.con.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
