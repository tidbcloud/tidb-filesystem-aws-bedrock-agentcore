"""The harness, not the runtime under test, decides isolation verdicts."""

from __future__ import annotations

import unittest

from isolation_grading import grade_permission, grade_visibility

SHARED = ":/agentcore-tests/unit-test/shared"


class PermissionGradingTests(unittest.TestCase):
    def test_runtime_claimed_pass_is_overridden_for_overprivileged_agent_c(self) -> None:
        body = {
            "status": "PASS",
            "expected_write_allowed": True,  # runtime/caller-controlled, must be ignored
            "actual_write_allowed": True,
            "actual_outside_scope_denied": True,
        }
        status, grading = grade_permission("agent-c", body)
        self.assertEqual(status, "FAIL")
        self.assertFalse(grading["harness_expected_write_allowed"])

    def test_expected_outcomes(self) -> None:
        for agent_id, write_allowed in (("agent-a", True), ("agent-b", True), ("agent-c", False)):
            with self.subTest(agent=agent_id):
                body = {"actual_write_allowed": write_allowed, "actual_outside_scope_denied": True}
                self.assertEqual(grade_permission(agent_id, body)[0], "PASS")

    def test_outside_scope_access_fails(self) -> None:
        body = {"actual_write_allowed": True, "actual_outside_scope_denied": False}
        self.assertEqual(grade_permission("agent-a", body)[0], "FAIL")

    def test_older_runtime_response_uses_outside_exit_code(self) -> None:
        body = {"actual_write_allowed": False, "outside_scope_read": {"exit_code": 1}}
        self.assertEqual(grade_permission("agent-c", body)[0], "PASS")
        body["outside_scope_read"] = {"exit_code": 0}
        self.assertEqual(grade_permission("agent-c", body)[0], "FAIL")

    def test_missing_or_non_boolean_observations_fail(self) -> None:
        for body in ({}, {"actual_write_allowed": "false", "actual_outside_scope_denied": True},
                     {"actual_write_allowed": False}):
            with self.subTest(body=body):
                self.assertEqual(grade_permission("agent-c", body)[0], "FAIL")

    def test_unknown_agent_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            grade_permission("agent-x", {"actual_write_allowed": False, "actual_outside_scope_denied": True})


class VisibilityGradingTests(unittest.TestCase):
    def test_runtime_claimed_pass_is_overridden_when_agent_c_can_see_shared(self) -> None:
        body = {"status": "PASS", "expected_visible": True, "actual_visible": True, "target": SHARED}
        status, grading = grade_visibility("agent-c", body, expected_target=SHARED)
        self.assertEqual(status, "FAIL")
        self.assertFalse(grading["harness_expected_visible"])

    def test_agent_c_hidden_from_shared_passes(self) -> None:
        body = {"actual_visible": False, "target": SHARED}
        self.assertEqual(grade_visibility("agent-c", body, expected_target=SHARED)[0], "PASS")

    def test_probe_of_a_different_target_fails(self) -> None:
        body = {"actual_visible": False, "target": ":/attacker/chosen"}
        self.assertEqual(grade_visibility("agent-c", body, expected_target=SHARED)[0], "FAIL")

    def test_missing_observation_fails(self) -> None:
        self.assertEqual(grade_visibility("agent-c", {"target": SHARED}, expected_target=SHARED)[0], "FAIL")


if __name__ == "__main__":
    unittest.main()
