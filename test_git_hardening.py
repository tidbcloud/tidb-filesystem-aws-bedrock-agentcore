"""Regression tests for git command execution through repository-local config.

These tests use the real `git` binary and a temporary directory in place of
the Drive9 FUSE mount. They do not need AWS or Drive9 access.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentcore_test_stub import install as install_agentcore_test_stub

PROJECT_DIR = Path(__file__).resolve().parents[1]
os.environ.setdefault("AGENT_ID", "agent-a")
os.environ.setdefault("TEST_RUN_ID", "unit-test")
os.environ.setdefault("DRIVE9_TEST_TOKEN", "unit-test-token")
os.environ.setdefault(
    "AUTHZ_DISCOVERY_URL",
    "https://issuer.example/.well-known/openid-configuration",
)
os.environ.setdefault("AUTHZ_ALLOWED_CLIENTS", "unit-test-client")
install_agentcore_test_stub()


def _load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


app = _load("agent_app", PROJECT_DIR / "app.py")


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class GitHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.staging = Path(self._tmp.name) / "staging"
        self.remote: dict[str, str] = {}
        self.marker = Path(self._tmp.name) / "pwned"
        self._original = (app.GIT_STAGING_ROOT, app._write_text, app._read_text, app._mounted)
        app.GIT_STAGING_ROOT = self.staging
        app._write_text = self._write_remote
        app._read_text = self._read_remote
        app._mounted = lambda _callback: (_ for _ in ()).throw(
            AssertionError("Git actions must never mount or execute against Drive9")
        )

    def tearDown(self) -> None:
        app.GIT_STAGING_ROOT, app._write_text, app._read_text, app._mounted = self._original
        self._tmp.cleanup()

    def _write_remote(self, relative: str, content: str, **_kwargs) -> dict:
        self.remote[relative] = content
        return {"exit_code": 0, "path": relative}

    def _read_remote(self, relative: str) -> dict:
        if relative not in self.remote:
            return {"exit_code": 1, "stdout": ""}
        return {"exit_code": 0, "stdout": self.remote[relative]}

    def _prepare(self) -> dict:
        result = app.action_git_prepare({"task_id": "git-001"})
        self.assertEqual(result["status"], "PASS")
        return result

    def _hostile_command(self) -> str:
        return f"touch {self.marker}"

    def test_clean_repository_round_trip(self) -> None:
        prepared = self._prepare()
        self.assertEqual(prepared["execution"], "tenant-local-unprivileged")
        self.assertEqual(prepared["snapshot"]["branch"], "feature/git-001")
        self.assertIn("?? dirty.txt", prepared["snapshot"]["status"])
        verified = app.action_git_verify({"task_id": "git-001"})
        self.assertEqual(verified["status"], "PASS")
        self.assertEqual(verified["execution"], "no-git-on-remote-content")
        self.assertEqual(verified["dirty_content"], "uncommitted work from agent-a\n")

    def test_peer_git_metadata_is_never_read_or_executed(self) -> None:
        self._prepare()
        self.remote["git-workspaces/git-001/.git/config"] = (
            f"[core]\n\tfsmonitor = {self._hostile_command()}\n"
        )
        with patch.object(
            app,
            "_run_local_git",
            side_effect=AssertionError("verify must not invoke Git"),
        ):
            result = app.action_git_verify({"task_id": "git-001"})
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(self.marker.exists())

    def test_command_text_in_remote_snapshot_is_data_only(self) -> None:
        prepared = self._prepare()
        snapshot = prepared["snapshot"]
        snapshot["dirty_content"] = self._hostile_command()
        self.remote[prepared["snapshot_path"]] = json.dumps(snapshot)
        verified = app.action_git_verify({"task_id": "git-001"})
        self.assertEqual(verified["dirty_content"], self._hostile_command())
        self.assertFalse(self.marker.exists())

    def test_invalid_remote_snapshot_is_rejected_without_git(self) -> None:
        self.remote["git-workspaces/git-001/snapshot.json"] = '{"schema":"wrong"}'
        with patch.object(
            app,
            "_run_local_git",
            side_effect=AssertionError("verify must not invoke Git"),
        ):
            with self.assertRaisesRegex(RuntimeError, "invalid schema"):
                app.action_git_verify({"task_id": "git-001"})

    def test_symlinked_local_staging_root_is_refused(self) -> None:
        target = Path(self._tmp.name) / "target"
        target.mkdir()
        self.staging.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "symlinked Git staging root"):
            self._prepare()

    def test_root_process_configures_non_root_git_identity(self) -> None:
        with patch.object(app.os, "geteuid", return_value=0):
            self.assertEqual(
                app._git_process_options(),
                {"user": 10000, "group": 10000, "extra_groups": []},
            )

    def test_git_environment_has_no_credentials(self) -> None:
        os.environ["AWS_SECRET_ACCESS_KEY"] = "unit-test-aws"
        try:
            env = app._git_env()
        finally:
            del os.environ["AWS_SECRET_ACCESS_KEY"]
        self.assertNotIn("DRIVE9_API_KEY", env)
        self.assertFalse(any(key.startswith("AWS_") for key in env))
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["PATH"], "/usr/bin:/bin")


class RemotePathTests(unittest.TestCase):
    def test_git_metadata_paths_are_rejected(self) -> None:
        for path in (
            "git-workspaces/git-001/.git/config",
            "git-workspaces/git-001/.git",
            ".git/config",
            "a/.GIT/hooks/post-checkout",
            "./x/.Git/config",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, ".git"):
                    app._remote(path)

    def test_normal_paths_are_unchanged(self) -> None:
        self.assertEqual(app._remote("functional/a.txt"), f"{app.BASE_REMOTE}/functional/a.txt")
        self.assertEqual(app._remote("x/.gitignore"), f"{app.BASE_REMOTE}/x/.gitignore")
        self.assertEqual(app._remote("x/my.git/file"), f"{app.BASE_REMOTE}/x/my.git/file")
@unittest.skipIf(shutil.which("git") is None, "git is not installed")
@unittest.skipUnless((PROJECT_DIR / "app.py.bak-20261103").exists(), "pre-fix backup not present")
class PreFixReproductionTests(unittest.TestCase):
    """Shows the planted fsmonitor executed with the original code."""

    def test_original_code_executes_planted_fsmonitor(self) -> None:
        original = _load("agent_app_prefix", PROJECT_DIR / "app.py.bak-20261103")
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp) / "mnt"
            mount.mkdir()
            marker = Path(tmp) / "pwned"
            original._mounted = lambda callback: {"status": "PASS", "callback": callback(mount)}
            original.action_git_prepare({"task_id": "git-001"})
            config = mount / "git-workspaces" / "git-001" / ".git" / "config"
            with config.open("a", encoding="utf-8") as handle:
                handle.write(f"[core]\n\tfsmonitor = touch {marker}\n")
            original.action_git_verify({"task_id": "git-001"})
            self.assertTrue(marker.exists(), "expected the pre-fix code to run the planted command")


if __name__ == "__main__":
    unittest.main()
