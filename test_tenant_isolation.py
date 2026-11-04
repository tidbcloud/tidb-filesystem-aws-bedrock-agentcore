"""Regression tests for per-runtime Drive9 remote-prefix confinement."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import unittest

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


def _load_app():
    name = "tenant_isolation_test_app"
    loader = importlib.machinery.SourceFileLoader(name, str(PROJECT_DIR / "app.py"))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


app = _load_app()


class RemotePathConfinementTests(unittest.TestCase):
    def test_drive9_absolute_paths_are_rejected(self) -> None:
        for path in (
            ":/",
            ":/agentcore-tests/another-run/shared/secret.txt",
            ":/agentcore-tests/unit-test/agent-c/file.txt",
            "://agentcore-tests/unit-test/shared/file.txt",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "relative to the agent root"):
                    app._remote(path)

    def test_other_escape_forms_are_rejected(self) -> None:
        for path in ("/etc/passwd", "../other-agent/file", "safe/../../other-run"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    app._remote(path)

    def test_relative_paths_remain_under_runtime_root(self) -> None:
        self.assertEqual(app._remote(None), app.BASE_REMOTE)
        self.assertEqual(app._remote("."), app.BASE_REMOTE)
        self.assertEqual(
            app._remote("functional/result.txt"),
            f"{app.BASE_REMOTE}/functional/result.txt",
        )

    def test_non_string_and_unsafe_character_paths_are_rejected(self) -> None:
        for path in (123, ["other-agent", "file"], "bad\\path", "line\nbreak"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    app._remote(path)

    def test_every_caller_path_sink_rejects_absolute_remote_paths_before_execution(self) -> None:
        outside = ":/agentcore-tests/another-run/shared/target.txt"
        original = (app._ensure_context, app._drive9_env, app._run)
        calls: list[list[str]] = []
        app._ensure_context = lambda: {"status": "ready"}
        app._drive9_env = lambda: {}
        app._run = lambda args, **_kwargs: calls.append(args) or {"exit_code": 0}
        cases = {
            "write": lambda: app.action_write({"path": outside, "content": "x"}),
            "append": lambda: app.action_append({"path": outside, "content": "x"}),
            "read": lambda: app.action_read({"path": outside}),
            "list": lambda: app.action_list({"path": outside}),
            "stat": lambda: app.action_stat({"path": outside}),
            "delete": lambda: app.action_delete({"path": outside}),
            "find": lambda: app.action_find({"path": outside}),
            "search": lambda: app.action_search({"path": outside, "query": "secret"}),
            "move-source": lambda: app.action_move(
                {"source": outside, "destination": "safe.txt"}
            ),
            "move-destination": lambda: app.action_move(
                {"source": "safe.txt", "destination": outside}
            ),
            "copy-source": lambda: app.action_copy(
                {"source": outside, "destination": "safe.txt"}
            ),
            "copy-destination": lambda: app.action_copy(
                {"source": "safe.txt", "destination": outside}
            ),
        }
        try:
            for name, invoke in cases.items():
                calls.clear()
                with self.subTest(action=name):
                    with self.assertRaisesRegex(ValueError, "relative to the agent root"):
                        invoke()
                    self.assertEqual(calls, [], "Drive9 must not execute for a rejected path")
        finally:
            app._ensure_context, app._drive9_env, app._run = original

    def test_network_handler_fails_closed_without_invoking_delete(self) -> None:
        original = (app._authenticate_request, app._ensure_context, app._drive9_env, app._run)
        called = False

        def run_marker(*_args, **_kwargs):
            nonlocal called
            called = True
            return {"exit_code": 0}

        app._authenticate_request = lambda _context: app.AuthorizedCaller(
            subject="admin-user",
            caller_id="test-caller",
            scopes=frozenset({app.AUTHZ_ADMIN_SCOPE}),
        )
        app._ensure_context = lambda: {"status": "ready"}
        app._drive9_env = lambda: {}
        app._run = run_marker
        try:
            result = app.handle_request(
                {"action": "delete", "path": ":/agentcore-tests/another-run/shared"}
            )
        finally:
            (
                app._authenticate_request,
                app._ensure_context,
                app._drive9_env,
                app._run,
            ) = original
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
