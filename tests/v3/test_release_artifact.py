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

    @unittest.skipUnless(hasattr(__import__("os"), "symlink"), "needs symlink support")
    def test_tree_symlink_fails_closed(self):
        import os
        self._build()
        os.symlink(self.root / "src/pkg/a.py", self.root / "src/pkg/link.py")
        with self.assertRaisesRegex(ValueError, "symlink"):
            verify_release.verify_tree(self.root)

    def test_tree_nonregular_entry_fails_closed(self):
        import os
        self._build()
        if not hasattr(os, "mkfifo"):
            self.skipTest("needs POSIX mkfifo")
        os.mkfifo(self.root / "src/pkg/pipe")
        with self.assertRaisesRegex(ValueError, "non-regular"):
            verify_release.verify_tree(self.root)


class ZipVerificationTests(unittest.TestCase):
    """Adversarial tests against the streaming ZIP-native verifier."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "proj"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src/a.py").write_bytes(b"print(1)\n")
        (self.root / "docs").mkdir()
        (self.root / "docs/readme.md").write_bytes(b"hi\n")
        files = build_release.inventory(self.root)
        self.manifest = {"schema": 1, "files": files}
        (self.root / "RELEASE_SHA256.json").write_text(
            json.dumps(self.manifest, sort_keys=True))
        self.zip_path = Path(self.temp.name) / "release.zip"

    def _zip(self, entries):
        import zipfile
        with zipfile.ZipFile(self.zip_path, "w") as z:
            for name, data in entries:
                z.writestr(name, data)
        return self.zip_path

    def _canonical_zip(self):
        return verify_release.build_zip(self.root, self.zip_path)

    def test_canonical_zip_verifies(self):
        self._canonical_zip()
        result = verify_release.verify(self.zip_path)
        self.assertTrue(result["valid"])
        self.assertEqual(result["source_files"], 2)
        self.assertEqual(result["manifest"], "RELEASE_SHA256.json")

    def test_build_is_deterministic(self):
        z1 = self._canonical_zip()
        digest1 = __import__("hashlib").sha256(z1.read_bytes()).hexdigest()
        self.zip_path = Path(self.temp.name) / "release2.zip"
        z2 = self._canonical_zip()
        digest2 = __import__("hashlib").sha256(z2.read_bytes()).hexdigest()
        self.assertEqual(digest1, digest2)

    def test_two_manifests_rejected(self):
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        self._zip([
            ("proj/src/a.py", b"print(1)\n"),
            ("proj/docs/readme.md", b"hi\n"),
            ("proj/RELEASE_SHA256.json", manifest),
            ("proj/SOURCE_SHA256.json", manifest),
        ])
        with self.assertRaisesRegex(ValueError, "manifest"):
            verify_release.verify(self.zip_path)

    def test_missing_manifest_rejected(self):
        self._zip([("proj/src/a.py", b"print(1)\n")])
        with self.assertRaisesRegex(ValueError, "manifest"):
            verify_release.verify(self.zip_path)

    def test_tampered_member_rejected(self):
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        self._zip([
            ("proj/src/a.py", b"print('pwned')\n"),
            ("proj/docs/readme.md", b"hi\n"),
            ("proj/RELEASE_SHA256.json", manifest),
        ])
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_release.verify(self.zip_path)

    def test_extra_member_rejected(self):
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        self._zip([
            ("proj/src/a.py", b"print(1)\n"),
            ("proj/docs/readme.md", b"hi\n"),
            ("proj/evil.py", b"import os\n"),
            ("proj/RELEASE_SHA256.json", manifest),
        ])
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_release.verify(self.zip_path)

    def test_missing_member_rejected(self):
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        self._zip([
            ("proj/src/a.py", b"print(1)\n"),
            ("proj/RELEASE_SHA256.json", manifest),
        ])
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_release.verify(self.zip_path)

    def test_duplicate_member_rejected(self):
        import zipfile
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        import warnings
        with zipfile.ZipFile(self.zip_path, "w") as z:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                z.writestr("proj/src/a.py", b"print(1)\n")
                z.writestr("proj/src/a.py", b"print(1)\n")
            z.writestr("proj/docs/readme.md", b"hi\n")
            z.writestr("proj/RELEASE_SHA256.json", manifest)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_release.verify(self.zip_path)

    def test_symlink_member_rejected(self):
        import zipfile
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        with zipfile.ZipFile(self.zip_path, "w") as z:
            z.writestr("proj/src/a.py", b"print(1)\n")
            z.writestr("proj/docs/readme.md", b"hi\n")
            z.writestr("proj/RELEASE_SHA256.json", manifest)
            link = zipfile.ZipInfo("proj/src/link.py")
            link.external_attr = (0o120777 << 16)
            link.create_system = 3
            z.writestr(link, "a.py")
        with self.assertRaisesRegex(ValueError, "symlink|unsafe"):
            verify_release.verify(self.zip_path)

    def test_traversal_member_rejected(self):
        import json as j
        manifest = j.dumps(self.manifest, sort_keys=True)
        self._zip([
            ("proj/src/a.py", b"print(1)\n"),
            ("proj/docs/readme.md", b"hi\n"),
            ("proj/../escape.py", b"x\n"),
            ("proj/RELEASE_SHA256.json", manifest),
        ])
        with self.assertRaisesRegex(ValueError, "unsafe|expected one project"):
            verify_release.verify(self.zip_path)

    def test_absolute_path_member_rejected(self):
        self._zip([
            ("/abs/path.py", b"x\n"),
            ("proj/RELEASE_SHA256.json", "junk"),
        ])
        with self.assertRaisesRegex(ValueError, "unsafe"):
            verify_release.verify(self.zip_path)

    def test_corrupted_zip_rejected(self):
        self.zip_path.write_bytes(b"not a zip at all")
        with self.assertRaises((ValueError, Exception)):
            verify_release.verify(self.zip_path)

    def test_attestation_outside_zip(self):
        self._canonical_zip()
        attest = verify_release.release_attestation(self.zip_path, self.root)
        self.assertEqual(attest["schema"], 1)
        self.assertEqual(attest["source_files"], 2)
        self.assertIn("zip_sha256", attest)
        self.assertIn("manifest_sha256", attest)


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
