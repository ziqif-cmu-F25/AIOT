"""Negative tests for the Stage 2 information boundary (AC-02).

Stage 2 counterpart of tools/access_control_tests.sh: proves that
driver/context_loader.py cannot read files outside a task's allow-list and
cannot read evaluator-side material even when a task file is edited to point
there. Run from the repository root:

    stage2/.venv/Scripts/python -m unittest discover -s stage2/tests -v
"""

from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
REPO = STAGE2.parent
sys.path.insert(0, str(STAGE2))

from driver import run_task  # noqa: E402
from driver.context_loader import (  # noqa: E402
    BoundaryError,
    IntegrityError,
    load_context,
)

# Every file opened while the audit flag is set is recorded here.
_OPENED: list[Path] = []
_RECORDING = False


def _audit(event, args):
    if _RECORDING and event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        try:
            _OPENED.append(Path(os.fsdecode(args[0])).resolve())
        except (OSError, ValueError):
            pass


sys.addaudithook(_audit)


@contextlib.contextmanager
def record_opens():
    global _RECORDING
    _OPENED.clear()
    _RECORDING = True
    try:
        yield _OPENED
    finally:
        _RECORDING = False


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SandboxTree(unittest.TestCase):
    """A throwaway repo/{evaluator,stage2/...} tree for destructive cases."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.stage2 = self.tmp / "stage2"
        self.fixtures = self.stage2 / "tasks" / "fixtures"
        self.fixtures.mkdir(parents=True)
        (self.stage2 / "vendor").mkdir()
        (self.stage2 / "scoring" / "ground_truth").mkdir(parents=True)
        self.evaluator = self.tmp / "evaluator"
        self.evaluator.mkdir()
        self.secret = b"vulnerability_id: SECRET\n"
        (self.evaluator / "ground_truth.yaml").write_bytes(self.secret)
        (self.stage2 / "scoring" / "ground_truth" / "t.yaml").write_bytes(self.secret)
        self.good = b"int ok(void) { return 0; }\n"
        (self.fixtures / "ok.c").write_bytes(self.good)
        (self.fixtures / "unlisted.c").write_bytes(b"int unlisted;\n")
        (self.fixtures / "MANIFEST.txt").write_text(
            f"{sha(self.good)}  ok.c  local\n"
            f"{sha(self.secret)}  ground_truth.yaml  local\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def task(self, *paths, root="tasks/fixtures"):
        return {"context": {"source_root": root, "files": [{"path": p} for p in paths]}}

    def assertRefused(self, task, exc=BoundaryError):
        with record_opens() as opened:
            with self.assertRaises(exc):
                load_context(task, stage2_root=self.stage2)
        leaked = [p for p in opened if p.is_relative_to(self.evaluator)
                  or p.is_relative_to(self.stage2 / "scoring")]
        self.assertEqual(leaked, [], "evaluator-side file was opened")

    def test_allowed_file_loads(self):
        ctx = load_context(self.task("ok.c"), stage2_root=self.stage2)
        self.assertEqual([f.path for f in ctx.files], ["ok.c"])

    def test_direct_evaluator_entry_absolute(self):
        self.assertRefused(self.task(str(self.evaluator / "ground_truth.yaml")))

    def test_direct_evaluator_entry_repo_relative(self):
        self.assertRefused(self.task("evaluator/ground_truth.yaml"))

    def test_dotdot_traversal(self):
        self.assertRefused(self.task("../../../evaluator/ground_truth.yaml"))

    def test_traversal_into_scoring(self):
        self.assertRefused(self.task("../../scoring/ground_truth/t.yaml"))

    def test_symlink_into_evaluator(self):
        link = self.fixtures / "ground_truth.yaml"
        try:
            link.symlink_to(self.evaluator / "ground_truth.yaml")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create symlinks here: {exc}")
        # MANIFEST even lists the secret's hash, so only the path check can stop it.
        self.assertRefused(self.task("ground_truth.yaml"))

    def test_source_root_pointed_at_evaluator(self):
        for root in ("../evaluator", "evaluator", str(self.evaluator), "scoring", "."):
            with self.subTest(root=root):
                self.assertRefused(self.task("ground_truth.yaml", root=root))

    def test_unlisted_existing_file_is_never_read(self):
        with record_opens() as opened:
            ctx = load_context(self.task("ok.c"), stage2_root=self.stage2)
        self.assertNotIn(self.fixtures / "unlisted.c", opened)
        self.assertEqual(set(opened), {self.fixtures / "ok.c", self.fixtures / "MANIFEST.txt"})
        self.assertNotIn("unlisted", ctx.render())

    def test_one_bad_entry_means_nothing_is_read(self):
        with record_opens() as opened:
            with self.assertRaises(BoundaryError):
                load_context(self.task("ok.c", "../../../evaluator/ground_truth.yaml"),
                             stage2_root=self.stage2)
        self.assertEqual(opened, [])

    def test_file_not_in_manifest(self):
        self.assertRefused(self.task("unlisted.c"), IntegrityError)

    def test_sha_mismatch(self):
        (self.fixtures / "ok.c").write_bytes(self.good + b"/* tampered */\n")
        self.assertRefused(self.task("ok.c"), IntegrityError)

    def test_missing_manifest(self):
        (self.fixtures / "MANIFEST.txt").unlink()
        self.assertRefused(self.task("ok.c"), IntegrityError)


class RealTreeBoundary(unittest.TestCase):
    """The committed tasks, through the real driver entry point."""

    def run_dry(self, task_arg):
        with record_opens() as opened, contextlib.redirect_stdout(io.StringIO()) as out:
            rc = run_task.main([task_arg, "--dry-run"])
        return rc, out.getvalue(), list(opened)

    def assert_no_evaluator_reads(self, opened):
        for p in opened:
            self.assertFalse(p.is_relative_to(REPO / "evaluator"), p)
            self.assertFalse(p.is_relative_to(STAGE2 / "scoring"), p)
            self.assertNotEqual(p, REPO / ".env", "dry run must not read secrets")

    def test_committed_tasks_read_only_their_allow_list(self):
        for task_id, allowed in {
            "demo-pattern": {STAGE2 / "tasks/fixtures/demo_snippet.c",
                             STAGE2 / "tasks/fixtures/MANIFEST.txt"},
            "shakedown-proxy-address": {STAGE2 / "vendor/src/coap_address.c",
                                        STAGE2 / "vendor/MANIFEST.txt"},
        }.items():
            with self.subTest(task=task_id):
                rc, prompt, opened = self.run_dry(task_id)
                self.assertEqual(rc, 0)
                self.assert_no_evaluator_reads(opened)
                in_repo = {p for p in opened if p.is_relative_to(REPO)
                           and not p.is_relative_to(STAGE2 / ".venv")
                           and "__pycache__" not in p.parts and ".git" not in p.parts}
                expected = allowed | {STAGE2 / f"tasks/{task_id}.yaml",
                                      STAGE2 / "schema/candidate_record.schema.json"}
                self.assertEqual(in_repo, expected)
                self.assertNotIn("CVE-", prompt)

    def test_edited_task_pointing_at_evaluator_is_refused(self):
        """Deliberately edit a copy of a real task file to reach evaluator/."""
        base = run_task.load_task(STAGE2 / "tasks" / "demo-pattern.yaml")
        attempts = {
            "absolute": ("tasks/fixtures", str(REPO / "evaluator" / "ground_truth.yaml")),
            "traversal": ("tasks/fixtures", "../../../evaluator/ground_truth.yaml"),
            "root": ("../evaluator", "ground_truth.yaml"),
            "scoring": ("tasks/fixtures", "../../scoring/ground_truth/demo-pattern.yaml"),
            "oracle": ("vendor", "../../evaluator/ORACLE.md"),
        }
        for name, (root, path) in attempts.items():
            with self.subTest(attempt=name):
                task = copy.deepcopy(base)
                task["context"] = {"source_root": root, "files": [{"path": path}]}
                with record_opens() as opened:
                    with self.assertRaises(BoundaryError):
                        load_context(task)
                self.assert_no_evaluator_reads(opened)

    def test_cli_exits_before_any_call_on_violation(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            text = (STAGE2 / "tasks" / "demo-pattern.yaml").read_text(encoding="utf-8")
            bad = tmp / "demo-pattern.yaml"
            bad.write_text(text.replace("path: demo_snippet.c",
                                        "path: ../../../evaluator/ground_truth.yaml"),
                           encoding="utf-8")
            calls = []
            with contextlib.redirect_stderr(io.StringIO()) as err:
                rc = run_task.main([str(bad), "--results-root", str(tmp / "out")],
                                   client_factory=lambda: calls.append(1))
            self.assertEqual(rc, 2)
            self.assertIn("refused", err.getvalue())
            self.assertEqual(calls, [], "client must not even be constructed")
            self.assertFalse((tmp / "out").exists(), "no run directory may be written")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class StaticSeparation(unittest.TestCase):
    """driver/ never imports scoring, never names evaluator paths, never fetches."""

    def sources(self):
        return {p.name: p.read_text(encoding="utf-8") for p in (STAGE2 / "driver").glob("*.py")}

    def test_no_scoring_imports(self):
        for name, src in self.sources().items():
            for node in ast.walk(ast.parse(src)):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or ""]
                for mod in mods:
                    with self.subTest(file=name, module=mod):
                        self.assertNotIn("scoring", mod)
                        self.assertNotIn("fetch_source", mod)
                        self.assertNotIn(mod.split(".")[0], {"urllib", "requests", "httpx", "socket"})

    def test_evaluator_named_only_in_deny_list(self):
        """The only path literal naming evaluator/ is the deny list in forbidden_dirs()."""
        def path_like(value):
            v = value.lower()
            return v.strip("/\\") == "evaluator" or "evaluator/" in v or "evaluator\\" in v

        locations = []
        for name, src in self.sources().items():
            for word in ("ground_truth", "ORACLE.md"):
                self.assertNotIn(word, src, f"{word!r} appears in driver/{name}")
            tree = ast.parse(src)
            for fn in ast.walk(tree):
                if not isinstance(fn, ast.FunctionDef):
                    continue
                for node in ast.walk(fn):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                            and path_like(node.value):
                        locations.append(f"{name}:{fn.name}")
            module_hits = [n for n in ast.walk(tree) if isinstance(n, ast.Constant)
                           and isinstance(n.value, str) and path_like(n.value)]
            self.assertLessEqual(len(module_hits), locations.count(f"{name}:forbidden_dirs"),
                                 f"evaluator path literal outside a function in driver/{name}")
        self.assertEqual(locations, ["context_loader.py:forbidden_dirs"])

    def test_score_run_is_separate_entry_point(self):
        score = (STAGE2 / "scoring" / "score_run.py").read_text(encoding="utf-8")
        self.assertIn('if __name__ == "__main__"', score)
        for name, src in self.sources().items():
            idents = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)} | \
                     {n.attr for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Attribute)}
            self.assertFalse({"score_run", "score_candidate"} & idents,
                             f"driver/{name} references scoring code")


if __name__ == "__main__":
    unittest.main()
