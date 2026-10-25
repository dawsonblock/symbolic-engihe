"""Worked skill-holdout examples: ingest -> probe -> qualify -> serve."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

SKILLS = {
    "write-skills": (
        "# Write skills\n\n"
        "- Trigger from the description: the frontmatter description is the "
        "only part read before the skill loads.\n"
        "- Keep the body short.\n"),
    "php2shell-check": (
        "# php2shell check\n\n"
        "- Docker official images: pin php:8.5.12, php:8.4.27, php:8.3.36 "
        "or php:8.2.35 and rebuild with --pull --no-cache.\n"
        "- Restart workers after the upgrade.\n"),
}


def _write_skills(root: Path, names=SKILLS) -> Path:
    for name, body in names.items():
        skill = root / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Use when testing {name}.\n"
            f"---\n\n{body}", encoding="utf-8")
    return root


class SkillHoldoutCLITests(unittest.TestCase):
    def _env(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + str(REPO)
        return env

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(REPO / "tools" / "skill_holdout.py"),
             *args],
            capture_output=True, text=True, env=self._env(), cwd=REPO,
            timeout=300)

    def test_two_worked_examples_qualify_and_serve(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills")
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "-o", str(report_path))
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            report = json.loads(report_path.read_text())
            self.assertEqual(report["kind"], "skill_holdout")
            self.assertEqual(report["missing_skills"], [])
            self.assertEqual([r["skill"] for r in report["results"]],
                             ["write-skills", "php2shell-check"])
            for entry in report["results"]:
                self.assertEqual(entry["status"], "qualified")
                self.assertEqual(entry["state"], "qualified")
                self.assertEqual(entry["probe"]["solved"]["A"], 0)
                self.assertEqual(entry["probe"]["solved"]["E"], 1)
                self.assertTrue(entry["probe"]["conformance"]["conforms"],
                                entry["probe"]["conformance"])
                self.assertTrue(entry["served"]["delivered_skill_steps"])
                self.assertEqual(entry["served"]["decision"], "abstain")
                self.assertEqual(entry["served"]["reason_code"],
                                 "no_qualified_procedure")
                self.assertEqual(len(entry["evidence_digest"]), 64)
                self.assertEqual(len(entry["decision_digest"]), 64)
            self.assertTrue(report["registry"]["verify"]["ok"])
            kinds = [row["kind"] for row in report["serving_audit"]]
            self.assertEqual(kinds, ["served_guidance", "serving_outcome"] * 2)

    def test_missing_skill_is_reported_and_fails_the_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills",
                          {"write-skills": SKILLS["write-skills"]})
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "-o", str(report_path))
            self.assertEqual(proc.returncode, 1)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["missing_skills"], ["php2shell-check"])
            statuses = {r["skill"]: r["status"] for r in report["results"]}
            self.assertEqual(statuses["write-skills"], "qualified")
            self.assertEqual(statuses["php2shell-check"], "missing_skill")

    def test_unrelated_guidance_cannot_pass_the_holdout(self):
        # The php fixture's guidance keyword is absent, so the scripted
        # agent leaves the vulnerable Dockerfile and the private test fails.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills", {
                "write-skills": SKILLS["write-skills"],
                "php2shell-check": (
                    "# php2shell check\n\n- Restart workers after the "
                    "upgrade.\n"),
            })
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "-o", str(report_path))
            self.assertEqual(proc.returncode, 1)
            report = json.loads(report_path.read_text())
            statuses = {r["skill"]: r["status"] for r in report["results"]}
            self.assertEqual(statuses["write-skills"], "qualified")
            self.assertEqual(statuses["php2shell-check"], "no_pass_evidence")
            php = next(r for r in report["results"]
                       if r["skill"] == "php2shell-check")
            self.assertEqual(php["probe"]["solved"], {"A": 0, "E": 0})


if __name__ == "__main__":
    unittest.main()
