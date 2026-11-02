"""Driver + scoring pipeline tests with a fake model client.

Fully mocked: no network, no API key, no tokens spent. Every run goes
through FakeClient via run_task.main(client_factory=...).

Covers the retry/malformed_output path, run-directory shape, repeats
summary, and score_run.py verdicts (AC-05). Run from the repository root:

    stage2/.venv/Scripts/python -m unittest discover -s stage2/tests -v
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

STAGE2 = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(STAGE2))

from driver import run_task  # noqa: E402
from driver.openrouter_client import Completion  # noqa: E402

CORRECT = (FIXTURES / "correct_candidate.json").read_text(encoding="utf-8")
WRONG = (FIXTURES / "wrong_candidate.json").read_text(encoding="utf-8")


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def complete(self, model, messages, sampling):
        self.calls.append({"model": model, "messages": messages, "sampling": sampling})
        return Completion(text=self.replies.pop(0), requested_model=model,
                          resolved_model=f"{model}-20990101", provider="FakeProvider",
                          response_id=f"gen-{len(self.calls)}", finish_reason="stop",
                          usage={"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
                                 "completion_tokens_details": {"reasoning_tokens": 5},
                                 "cost": 0.0001},
                          created=0)


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def drive(self, replies, *extra, task="demo-pattern"):
        client = FakeClient(replies)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = run_task.main([task, "--results-root", str(self.out), "--model", "fake/model",
                                "--cost-log", str(self.out / "cost_log.csv"), *extra],
                               client_factory=lambda: client)
        return rc, client

    def score(self, run_dir, task="demo-pattern"):
        proc = subprocess.run(
            [sys.executable, str(STAGE2 / "scoring" / "score_run.py"), "--task", task, "--run", str(run_dir)],
            capture_output=True, text=True,
        )
        return proc

    def test_valid_output_writes_full_run_directory(self):
        rc, client = self.drive([CORRECT])
        self.assertEqual(rc, 0)
        run = self.out / "run-001"
        for name in ("run.yaml", "findings.md", "notes.md", "commands.log", "verdict.md",
                     "prompt.txt", "transcript.json", "candidates.json"):
            self.assertTrue((run / name).is_file(), name)
        meta = yaml.safe_load((run / "run.yaml").read_text(encoding="utf-8"))
        self.assertEqual(meta["status"], "candidate")
        self.assertEqual(meta["viewpoint"], "ai-source-review")
        self.assertEqual(meta["model_requested"], "fake/model")
        self.assertEqual(meta["model_resolved"], ["fake/model-20990101"])
        self.assertEqual(meta["sampling"]["temperature"], 0.0)
        self.assertEqual(client.calls[0]["sampling"]["temperature"], 0.0)
        rec = json.loads((run / "candidates.json").read_text(encoding="utf-8"))[0]
        self.assertEqual((rec["status"], rec["oracle_verdict"]), ("candidate", "pending"))
        self.assertEqual(rec["prompt_id"], "demo-pattern@v1")
        self.assertIn("pending", (run / "verdict.md").read_text(encoding="utf-8"))
        self.assertNotIn("withheld", client.calls[0]["messages"][0]["content"].lower())

    def test_usage_total_and_cost_log(self):
        bad = CORRECT.replace('"buffer-overflow"', '"stack-smash"')
        self.drive([bad, CORRECT])          # two attempts in one run
        self.drive([CORRECT])
        meta = yaml.safe_load((self.out / "run-001" / "run.yaml").read_text(encoding="utf-8"))
        self.assertEqual(meta["usage_total"], {"prompt_tokens": 200, "completion_tokens": 40,
                                               "total_tokens": 240, "reasoning_tokens": 10,
                                               "cost_usd": 0.0002})
        with (self.out / "cost_log.csv").open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual([r["run_id"] for r in rows], ["run-001", "run-002"])
        self.assertEqual((rows[0]["attempts"], rows[0]["total_tokens"], rows[0]["cost_usd"]),
                         ("2", "240", "0.0002"))
        self.assertEqual(rows[0]["model_resolved"], "fake/model-20990101|fake/model-20990101")

    def test_task_without_temperature_is_rejected(self):
        text = (STAGE2 / "tasks" / "demo-pattern.yaml").read_text(encoding="utf-8")
        bad = self.out / "demo-pattern.yaml"
        bad.write_text(text.replace("  temperature: 0.0\n", ""), encoding="utf-8")
        calls = []
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = run_task.main([str(bad), "--results-root", str(self.out / "r")],
                               client_factory=lambda: calls.append(1))
        self.assertEqual(rc, 2)
        self.assertIn("model.temperature is required", err.getvalue())
        self.assertEqual(calls, [])

    def test_model_cannot_set_driver_owned_fields(self):
        data = json.loads(CORRECT)
        data["candidates"][0]["status"] = "validated"
        rc, _ = self.drive([json.dumps(data), json.dumps(data)])
        meta = yaml.safe_load((self.out / "run-001" / "run.yaml").read_text(encoding="utf-8"))
        self.assertEqual(meta["status"], "malformed_output")  # additionalProperties: false

    def test_invalid_class_retries_once_with_error(self):
        bad = CORRECT.replace('"buffer-overflow"', '"stack-smash"')
        rc, client = self.drive([bad, CORRECT])
        self.assertEqual(rc, 0)
        self.assertEqual(len(client.calls), 2)
        retry_msg = client.calls[1]["messages"][-1]["content"]
        self.assertIn("vulnerability_class", retry_msg)
        self.assertIn("stack-smash", retry_msg)
        meta = yaml.safe_load((self.out / "run-001" / "run.yaml").read_text(encoding="utf-8"))
        self.assertEqual((meta["status"], meta["attempts"]), ("candidate", 2))

    def test_twice_invalid_is_malformed_output(self):
        rc, client = self.drive(["not json at all", '{"candidates": "nope"}'])
        self.assertEqual(rc, 1)
        self.assertEqual(len(client.calls), 2)
        run = self.out / "run-001"
        meta = yaml.safe_load((run / "run.yaml").read_text(encoding="utf-8"))
        self.assertEqual(meta["status"], "malformed_output")
        raw = (run / "raw_output.txt").read_text(encoding="utf-8")
        self.assertIn("not json at all", raw)
        self.assertEqual(json.loads((run / "candidates.json").read_text(encoding="utf-8")), [])
        proc = self.score(run)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        v = yaml.safe_load((run / "verdict.yaml").read_text(encoding="utf-8"))
        self.assertEqual(v["run_verdict"], "inconclusive")

    def test_repeats_write_separate_runs_and_summary(self):
        rc, _ = self.drive([CORRECT, CORRECT, WRONG], "--repeats", "3")
        self.assertEqual(rc, 0)
        runs = sorted(p.name for p in self.out.glob("run-*"))
        self.assertEqual(runs, ["run-001", "run-002", "run-003"])
        summary = yaml.safe_load((self.out / "groups" / "group-001.yaml").read_text(encoding="utf-8"))
        self.assertEqual(summary["schema_valid_runs"], 3)
        self.assertFalse(summary["top_candidate_unanimous"])
        self.assertEqual(summary["top_candidate_lines"], ["3", "4"])
        idx = [yaml.safe_load((self.out / r / "run.yaml").read_text(encoding="utf-8"))["run_index"]
               for r in runs]
        self.assertEqual(idx, [1, 2, 3])

    def test_score_correct_validated_wrong_false_positive(self):
        self.drive([CORRECT])
        self.drive([WRONG])
        ok, wrong = self.out / "run-001", self.out / "run-002"
        for run in (ok, wrong):
            proc = self.score(run)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        v_ok = yaml.safe_load((ok / "verdict.yaml").read_text(encoding="utf-8"))
        v_wrong = yaml.safe_load((wrong / "verdict.yaml").read_text(encoding="utf-8"))
        self.assertEqual(v_ok["run_verdict"], "validated")
        self.assertEqual(v_ok["candidates"][0]["oracle_verdict"], "true_positive")
        self.assertEqual(v_wrong["run_verdict"], "rejected")
        self.assertEqual(v_wrong["candidates"][0]["oracle_verdict"], "false_positive")
        # original evidence untouched
        rec = json.loads((ok / "candidates.json").read_text(encoding="utf-8"))[0]
        self.assertEqual((rec["status"], rec["oracle_verdict"]), ("candidate", "pending"))

    def test_score_partial_line_is_inconclusive(self):
        self.drive([CORRECT.replace('"line": 3', '"line": 1')])
        self.score(self.out / "run-001")
        v = yaml.safe_load((self.out / "run-001" / "verdict.yaml").read_text(encoding="utf-8"))
        self.assertEqual(v["candidates"][0]["oracle_verdict"], "location_partial_match")

    def test_score_refuses_task_mismatch(self):
        self.drive([CORRECT])
        proc = self.score(self.out / "run-001", task="shakedown-proxy-address")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not 'shakedown-proxy-address'", proc.stderr)

    def test_shakedown_runs_with_no_driver_changes(self):
        reply = json.dumps({"candidates": [{
            "hypothesis": "h", "evidence_source": "e", "expected_behavior": "x", "notes": "",
            "vulnerability_class": "buffer-overflow", "confidence": 0.9,
            "location": {"file": "src/coap_address.c", "function": "coap_resolve_address_info",
                         "line": 538}}]})
        rc, client = self.drive([reply], task="shakedown-proxy-address")
        self.assertEqual(rc, 0)
        prompt = client.calls[0]["messages"][0]["content"]
        self.assertIn("=== FILE: src/coap_address.c (lines 1-849 of 849) ===", prompt)
        for leak in ("CVE-", "30db3eaa", "coap_resolve_address_info is", "-P,"):
            self.assertNotIn(leak, prompt)
        proc = self.score(self.out / "run-001", task="shakedown-proxy-address")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        v = yaml.safe_load((self.out / "run-001" / "verdict.yaml").read_text(encoding="utf-8"))
        self.assertEqual(v["run_verdict"], "validated")
        self.assertEqual(v["references"][0]["recorded"]["vulnerability_id"], "CVE-2025-34468")


if __name__ == "__main__":
    unittest.main()
