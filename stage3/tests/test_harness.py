"""Loop and tool-boundary tests. No network and no API key."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

STAGE3 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE3))

from harness.controller import run_loop
from harness.run_harness import main
from harness.target_config import TargetError, load_target
from harness.tools import ToolBox, ToolError
from scripts.relay_docker import guest_path, place_input


FIXTURE = STAGE3 / "targets" / "fixture-mini.yaml"
SCRIPTED = STAGE3 / "targets" / "fixture" / "scripted_actions.json"


class HarnessTests(unittest.TestCase):
    def test_scripted_run_finishes_with_pending_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status = main([
                str(FIXTURE),
                "--scripted", str(SCRIPTED),
                "--results-root", str(root / "results"),
                "--cost-log", str(root / "cost_log.csv"),
            ])
            self.assertEqual(status, 0)
            run = next((root / "results").glob("run-*"))
            candidate = json.loads((run / "candidate.json").read_text(encoding="utf-8"))
            self.assertEqual(candidate["oracle_verdict"], "pending")
            self.assertEqual(candidate["status"], "candidate")
            transcript = (run / "transcript.json").read_text(encoding="utf-8")
            self.assertIn("copy exceeds 8-byte stack buffer", transcript)
            self.assertIn("stop_reason: finish", (run / "run.yaml").read_text(encoding="utf-8"))

    def test_invalid_json_is_returned_as_an_observation(self) -> None:
        pack = load_target(FIXTURE)
        with tempfile.TemporaryDirectory() as tmp:
            box = ToolBox(pack, Path(tmp), source_only=False)

            class Once:
                def __init__(self):
                    self.calls = 0

                def complete(self, messages):
                    del messages
                    self.calls += 1
                    if self.calls == 1:
                        return "I think there is a bug"
                    return json.dumps({
                        "action": "finish",
                        "hypothesis": "stopping after a bad turn",
                        "candidate": {
                            "property": "",
                            "trigger_input": "",
                            "expected_evidence": "",
                            "confidence": 0,
                            "notes": "",
                        },
                    })

            outcome = run_loop(pack, box, Once())
            self.assertEqual(outcome.stop_reason, "finish")
            self.assertIn("not one JSON object", outcome.messages[3]["content"])

    def test_source_path_cannot_escape_root(self) -> None:
        pack = load_target(FIXTURE)
        with tempfile.TemporaryDirectory() as tmp:
            box = ToolBox(pack, Path(tmp), source_only=False)
            with self.assertRaises(ToolError):
                box.read_source({
                    "path": "../../evaluator/ground_truth.yaml",
                    "start_line": 1,
                    "end_line": 5,
                })

    def test_source_only_blocks_execution(self) -> None:
        pack = load_target(FIXTURE)
        with tempfile.TemporaryDirectory() as tmp:
            box = ToolBox(pack, Path(tmp), source_only=True)
            with self.assertRaises(ToolError):
                box.dispatch("run_target", {"input_text": "TAG-overflow"})

    def test_each_run_target_keeps_its_own_input_file(self) -> None:
        pack = load_target(FIXTURE)
        with tempfile.TemporaryDirectory() as tmp:
            box = ToolBox(pack, Path(tmp) / "scratch", source_only=False)
            box.run_target({"input_text": "one"})
            box.run_target({"input_text": "two"})
            saved = sorted((Path(tmp) / "scratch").glob("input-*.bin"))
            self.assertEqual([p.name for p in saved], ["input-001.bin", "input-002.bin"])
            self.assertEqual(saved[0].read_text(encoding="utf-8"), "one")
            self.assertEqual(saved[1].read_text(encoding="utf-8"), "two")

    def test_relay_places_a_distinct_guest_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input-001.bin"
            source.write_bytes(b"abc")
            dest = place_input(root / "mounted", source)
            self.assertEqual(dest.read_bytes(), b"abc")
            self.assertEqual(
                guest_path("/workspace/results/stage3-inputs", dest.name),
                "/workspace/results/stage3-inputs/input-001.bin",
            )

    def test_missing_target_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("target_id: x\n", encoding="utf-8")
            with self.assertRaises(TargetError):
                load_target(path)


if __name__ == "__main__":
    unittest.main()
