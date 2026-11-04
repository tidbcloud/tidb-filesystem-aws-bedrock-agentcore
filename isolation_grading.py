"""Harness-side grading for least-privilege and isolation tests.

The runtime under test reports observations (actual_*). Whether those
observations satisfy the isolation policy is decided here, from a policy the
harness owns, so a runtime or a caller cannot certify its own isolation.
"""

from __future__ import annotations

from typing import Any

HARNESS_ISOLATION_POLICY: dict[str, dict[str, bool]] = {
    "agent-a": {"write_allowed": True, "shared_visible": True},
    "agent-b": {"write_allowed": True, "shared_visible": True},
    "agent-c": {"write_allowed": False, "shared_visible": False},
}


def _policy(agent_id: str) -> dict[str, bool]:
    try:
        return HARNESS_ISOLATION_POLICY[agent_id]
    except KeyError:
        raise ValueError(f"no isolation policy for agent {agent_id!r}") from None


def _observed_bool(body: dict[str, Any], key: str) -> bool | None:
    value = body.get(key)
    return value if isinstance(value, bool) else None


def grade_permission(agent_id: str, body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    expected = _policy(agent_id)["write_allowed"]
    write_allowed = _observed_bool(body, "actual_write_allowed")
    outside_denied = _observed_bool(body, "actual_outside_scope_denied")
    if outside_denied is None:
        outside = body.get("outside_scope_read")
        if isinstance(outside, dict) and isinstance(outside.get("exit_code"), int):
            outside_denied = outside["exit_code"] != 0
    passed = write_allowed is not None and outside_denied is True and write_allowed == expected
    return ("PASS" if passed else "FAIL"), {
        "harness_expected_write_allowed": expected,
        "observed_write_allowed": write_allowed,
        "observed_outside_scope_denied": outside_denied,
    }


def grade_visibility(
    agent_id: str, body: dict[str, Any], *, expected_target: str
) -> tuple[str, dict[str, Any]]:
    expected = _policy(agent_id)["shared_visible"]
    visible = _observed_bool(body, "actual_visible")
    target = body.get("target")
    passed = visible is not None and visible == expected and target == expected_target
    return ("PASS" if passed else "FAIL"), {
        "harness_expected_visible": expected,
        "harness_expected_target": expected_target,
        "observed_visible": visible,
        "observed_target": target,
    }
