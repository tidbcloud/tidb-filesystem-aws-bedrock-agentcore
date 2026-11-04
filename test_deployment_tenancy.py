"""Tests for fail-closed per-tenant deployment resource bindings."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from deployment_tenancy import (
    AGENT_IDS,
    load_tenant_resources,
    validate_secret_access_decisions,
)


def valid_environment() -> dict[str, str]:
    return {
        "AGENT_RUNTIME_ROLE_ARN_AGENT_A": "arn:aws:iam::123456789012:role/Drive9AgentA",
        "AGENT_RUNTIME_ROLE_ARN_AGENT_B": "arn:aws:iam::123456789012:role/Drive9AgentB",
        "AGENT_RUNTIME_ROLE_ARN_AGENT_C": "arn:aws:iam::123456789012:role/Drive9AgentC",
        "CAPACITY_PROVIDER_VOLUME_NAME_AGENT_A": "scratch-agent-a",
        "CAPACITY_PROVIDER_VOLUME_NAME_AGENT_B": "scratch-agent-b",
        "CAPACITY_PROVIDER_VOLUME_NAME_AGENT_C": "scratch-agent-c",
        "DRIVE9_SECRET_ID_AGENT_A": "drive9/run/agent-a",
        "DRIVE9_SECRET_ID_AGENT_B": "drive9/run/agent-b",
        "DRIVE9_SECRET_ID_AGENT_C": "drive9/run/agent-c",
    }


def load(values: dict[str, str]):
    return load_tenant_resources(
        secret_prefix="drive9/test",
        test_run_id="unit-test",
        getenv=values.get,
    )


class DeploymentTenancyTests(unittest.TestCase):
    def test_each_agent_gets_its_own_role_volume_and_secret(self) -> None:
        resources = load(valid_environment())
        self.assertEqual(set(resources), set(AGENT_IDS))
        self.assertEqual(len({item.runtime_role_arn for item in resources.values()}), 3)
        self.assertEqual(len({item.volume_name for item in resources.values()}), 3)
        self.assertEqual(len({item.secret_id for item in resources.values()}), 3)

    def test_shared_runtime_role_is_rejected(self) -> None:
        values = valid_environment()
        values["AGENT_RUNTIME_ROLE_ARN_AGENT_C"] = values["AGENT_RUNTIME_ROLE_ARN_AGENT_A"]
        with self.assertRaisesRegex(RuntimeError, "distinct runtime role ARN"):
            load(values)

    def test_shared_volume_is_rejected(self) -> None:
        values = valid_environment()
        values["CAPACITY_PROVIDER_VOLUME_NAME_AGENT_B"] = values[
            "CAPACITY_PROVIDER_VOLUME_NAME_AGENT_A"
        ]
        with self.assertRaisesRegex(RuntimeError, "distinct capacity provider volume"):
            load(values)

    def test_shared_secret_is_rejected(self) -> None:
        values = valid_environment()
        values["DRIVE9_SECRET_ID_AGENT_B"] = values["DRIVE9_SECRET_ID_AGENT_A"]
        with self.assertRaisesRegex(RuntimeError, "distinct Drive9 secret ID"):
            load(values)

    def test_legacy_shared_role_variable_is_not_accepted(self) -> None:
        values = {"AGENT_RUNTIME_ROLE_ARN": "arn:aws:iam::123456789012:role/Shared"}
        with self.assertRaisesRegex(RuntimeError, "AGENT_RUNTIME_ROLE_ARN_AGENT_A"):
            load(values)

    def test_iam_decisions_allow_only_each_tenants_own_secret(self) -> None:
        resources = load(valid_environment())
        secret_arns = {
            agent_id: f"arn:aws:secretsmanager:us-east-2:123456789012:secret:{agent_id}"
            for agent_id in AGENT_IDS
        }
        decisions = {
            (tenant.runtime_role_arn, secret_arn): (
                "allowed" if owner == agent_id else "implicitDeny"
            )
            for agent_id, tenant in resources.items()
            for owner, secret_arn in secret_arns.items()
        }
        validate_secret_access_decisions(resources, secret_arns, decisions)

    def test_iam_cross_tenant_secret_access_is_rejected(self) -> None:
        resources = load(valid_environment())
        secret_arns = {
            agent_id: f"arn:aws:secretsmanager:us-east-2:123456789012:secret:{agent_id}"
            for agent_id in AGENT_IDS
        }
        decisions = {
            (tenant.runtime_role_arn, secret_arn): (
                "allowed" if owner == agent_id else "implicitDeny"
            )
            for agent_id, tenant in resources.items()
            for owner, secret_arn in secret_arns.items()
        }
        decisions[(resources["agent-a"].runtime_role_arn, secret_arns["agent-c"])] = "allowed"
        with self.assertRaisesRegex(RuntimeError, "agent-a can read agent-c"):
            validate_secret_access_decisions(resources, secret_arns, decisions)

    def test_iam_role_must_read_its_own_secret(self) -> None:
        resources = load(valid_environment())
        secret_arns = {
            agent_id: f"arn:aws:secretsmanager:us-east-2:123456789012:secret:{agent_id}"
            for agent_id in AGENT_IDS
        }
        decisions = {
            (tenant.runtime_role_arn, secret_arn): "implicitDeny"
            for tenant in resources.values()
            for secret_arn in secret_arns.values()
        }
        with self.assertRaisesRegex(RuntimeError, "agent-a is not allowed"):
            validate_secret_access_decisions(resources, secret_arns, decisions)


if __name__ == "__main__":
    unittest.main()
