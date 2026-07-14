import subprocess
import tempfile
import unittest
from pathlib import Path

import public_boundary_check as boundary


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "public-boundary-check.yml"


class PublicBoundaryUnitTests(unittest.TestCase):
    def test_current_public_paths_are_allowlisted(self):
        paths = (
            "README.md",
            "questions_v6.csv",
            "free_questions.csv",
            "results/2026-07/README.md",
            "results/2026-07/ranking.md",
            "results/2026-07/summary.csv",
            "results/2026-07/corrections/2026-07-13/CORRECTION.md",
            "results/2026-07/corrections/2026-07-13/ranking.md",
            "results/2026-07/corrections/2026-07-13/summary.csv",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(boundary.is_allowed_public_path(path))

    def test_unknown_and_private_paths_are_rejected(self):
        self.assertFalse(boundary.is_allowed_public_path("answers.md"))
        self.assertEqual(
            boundary.private_path_label("raw/2026-08/observation_2026-08.csv"),
            "private directory",
        )
        self.assertEqual(
            boundary.private_path_label("results/2026-08/observation_2026-08.csv"),
            "private filename",
        )

    def test_csv_policy_accepts_only_public_schemas(self):
        public_summary = (
            "region,category,official_name,engine,model_id,mention_count,total_score,status\n"
        )
        self.assertIsNone(
            boundary.csv_policy_label("results/2026-08/summary.csv", public_summary)
        )
        private_observation = (
            "question_id,engine,run,answer,citation_urls,request_id,executed_at\n"
        )
        self.assertEqual(
            boundary.csv_policy_label(
                "results/2026-08/summary.csv", private_observation
            ),
            "private CSV columns",
        )

    def test_secret_values_are_detected_without_being_needed_as_fixtures(self):
        token = "sk-" + ("A" * 30)
        self.assertIn("OpenAI token", boundary.secret_labels(token))
        assignment = "OPENAI_API_KEY=" + ("B" * 24)
        self.assertIn("literal OPENAI_API_KEY", boundary.secret_labels(assignment))
        self.assertFalse(boundary.secret_labels("OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }}"))

    def test_urls_are_rejected_from_result_artifacts(self):
        self.assertTrue(
            boundary.result_artifact_contains_url(
                "results/2026-08/ranking.md", "出典: https://example.com/private"
            )
        )
        self.assertFalse(
            boundary.result_artifact_contains_url(
                "README.md", "公開説明: https://example.com/"
            )
        )

    def test_tracked_tree_rejects_disguised_private_csv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            target = root / "results" / "2026-08" / "summary.csv"
            target.parent.mkdir(parents=True)
            target.write_text(
                "question_id,engine,run,answer,citation_urls,request_id,executed_at\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            findings, _ = boundary.scan_tracked_tree(root)
            self.assertIn("private CSV columns", {item.label for item in findings})

    def test_actual_repository_tree_passes(self):
        findings, path_count = boundary.scan_tracked_tree(ROOT)
        self.assertEqual(findings, [])
        self.assertGreaterEqual(path_count, 3)


class PublicBoundaryWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_runs_for_public_prs_and_main(self):
        self.assertIn("pull_request:", self.workflow)
        self.assertIn("push:", self.workflow)
        self.assertIn("- main", self.workflow)
        self.assertIn("python public_boundary_check.py --history", self.workflow)

    def test_has_read_only_permissions_and_no_secrets(self):
        self.assertIn("contents: read", self.workflow)
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("secrets.", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn("fetch-depth: 0", self.workflow)

    def test_actions_are_pinned(self):
        self.assertIn(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            self.workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            self.workflow,
        )


if __name__ == "__main__":
    unittest.main()
