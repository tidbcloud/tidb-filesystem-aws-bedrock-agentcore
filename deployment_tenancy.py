"""Fail-closed per-tenant resource configuration for AgentCore deployment."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Mapping


AGENT_IDS = ("agent-a", "agent-b", "agent-c")
_ROLE_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}"
)
_VOLUME_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,47}")


@dataclass(frozen=True)
class TenantResources:
    agent_id: str
    runtime_role_arn: str
    volume_name: str
    secret_id: str


def _suffix(agent_id: str) -> str:
    return agent_id.replace("-", "_").upper()


def load_tenant_resources(
    *,
    secret_prefix: str,
    test_run_id: str,
    getenv: Callable[[str, str], str] = os.getenv,
) -> dict[str, TenantResources]:
    resources: dict[str, TenantResources] = {}
    for agent_id in AGENT_IDS:
        suffix = _suffix(agent_id)
        role_arn = getenv(f"AGENT_RUNTIME_ROLE_ARN_{suffix}", "").strip()
        if not role_arn:
            raise RuntimeError(
                f"environment variable AGENT_RUNTIME_ROLE_ARN_{suffix} is required; "
                "runtime roles must not be shared between tenants"
            )
        volume_name = getenv(
            f"CAPACITY_PROVIDER_VOLUME_NAME_{suffix}", f"scratch-{agent_id}"
        ).strip()
        secret_id = getenv(
            f"DRIVE9_SECRET_ID_{suffix}", f"{secret_prefix}/{test_run_id}-{agent_id}"
        ).strip()
        if not _ROLE_ARN.fullmatch(role_arn):
            raise RuntimeError(f"runtime role ARN for {agent_id} is invalid")
        if not _VOLUME_NAME.fullmatch(volume_name):
            raise RuntimeError(f"capacity provider volume name for {agent_id} is invalid")
        if not secret_id or len(secret_id) > 2048 or any(ord(char) < 33 for char in secret_id):
            raise RuntimeError(f"Drive9 secret ID for {agent_id} is invalid")
        resources[agent_id] = TenantResources(
            agent_id=agent_id,
            runtime_role_arn=role_arn,
            volume_name=volume_name,
            secret_id=secret_id,
        )

    unique_fields = {
        "runtime role ARN": [item.runtime_role_arn for item in resources.values()],
        "capacity provider volume": [item.volume_name for item in resources.values()],
        "Drive9 secret ID": [item.secret_id for item in resources.values()],
    }
    for label, values in unique_fields.items():
        if len(set(values)) != len(AGENT_IDS):
            raise RuntimeError(f"each tenant must have a distinct {label}")
    return resources


def validate_secret_access_decisions(
    resources: Mapping[str, TenantResources],
    secret_arns: Mapping[str, str],
    decisions: Mapping[tuple[str, str], str],
) -> None:
    """Require each runtime role to read only its own tenant Secret."""
    if set(resources) != set(AGENT_IDS) or set(secret_arns) != set(AGENT_IDS):
        raise RuntimeError("IAM isolation validation requires all three tenants")
    if len(set(secret_arns.values())) != len(AGENT_IDS):
        raise RuntimeError("tenant Secret IDs must resolve to three distinct Secret ARNs")
    for agent_id, tenant in resources.items():
        own_arn = secret_arns[agent_id]
        own_decision = decisions.get((tenant.runtime_role_arn, own_arn), "missing").lower()
        if own_decision != "allowed":
            raise RuntimeError(
                f"runtime role for {agent_id} is not allowed to read its own Drive9 Secret"
            )
        for other_agent, other_arn in secret_arns.items():
            if other_agent == agent_id:
                continue
            cross_decision = decisions.get(
                (tenant.runtime_role_arn, other_arn), "missing"
            ).lower()
            if cross_decision == "allowed":
                raise RuntimeError(
                    f"runtime role for {agent_id} can read {other_agent}'s Drive9 Secret"
                )
