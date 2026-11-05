"""Deploy three ARM64 AgentCore Runtime Instances for Drive9 validation.

The Capacity Provider API is newer than the regular AgentCore data-plane API.
Some boto3 releases expose Runtime/Invoke operations but not Capacity Provider
operations, so this script supports both boto3 and the AWS CLI. ``auto``
selects boto3 only when all required control-plane operations are present;
otherwise it uses ``aws bedrock-agentcore-control``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

try:
    import boto3
except ImportError:  # The CLI-only path does not require boto3 on the host.
    boto3 = None  # type: ignore[assignment]

from deployment_tenancy import (
    AGENT_IDS,
    TenantResources,
    load_tenant_resources,
    validate_secret_access_decisions,
)


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"environment variable {name} is required")
    return value


def csv_env(name: str) -> list[str]:
    return [value.strip() for value in os.getenv(name, "").split(",") if value.strip()]


REGION = os.getenv("AWS_REGION", "us-east-2").strip()
IMAGE_URI = required("IMAGE_URI")
OPERATOR_ROLE_ARN = required("CAPACITY_PROVIDER_OPERATOR_ROLE_ARN")
SUBNETS = [value.strip() for value in required("SUBNET_IDS").split(",") if value.strip()]
SECURITY_GROUPS = [value.strip() for value in required("SECURITY_GROUP_IDS").split(",") if value.strip()]
TEST_RUN_ID = required("TEST_RUN_ID")
INSTANCE_TYPE = os.getenv("INSTANCE_TYPE", "c6g.large").strip()
OPERATING_SYSTEM = os.getenv("OPERATING_SYSTEM", "LINUX_ARM64").strip().upper()
ARCHITECTURE = "arm64"
CAPACITY_PROVIDER_NAME = os.getenv("CAPACITY_PROVIDER_NAME", "drive9_arm64_cp").strip()
VOLUME_SIZE_GIB = int(os.getenv("CAPACITY_PROVIDER_VOLUME_SIZE_GIB", "20"))
PROVIDER_MAX_LIFETIME = int(os.getenv("PROVIDER_MAX_LIFETIME", "3600"))
PROVIDER_IDLE_TIMEOUT = int(os.getenv("PROVIDER_IDLE_TIMEOUT", "900"))
RUNTIME_MAX_LIFETIME = int(os.getenv("RUNTIME_MAX_LIFETIME", "1800"))
RUNTIME_IDLE_TIMEOUT = int(os.getenv("RUNTIME_IDLE_TIMEOUT", "300"))
DRIVE9_SERVER = os.getenv("DRIVE9_SERVER", "https://api.drive9.ai").rstrip("/")
DRIVE9_SHARED_BASE_REMOTE = os.getenv(
    "DRIVE9_SHARED_BASE_REMOTE", f":/agentcore-tests/{TEST_RUN_ID}/shared"
).rstrip("/")
DRIVE9_AGENT_C_BASE_REMOTE = os.getenv(
    "DRIVE9_AGENT_C_BASE_REMOTE", f":/agentcore-tests/{TEST_RUN_ID}/agent-c"
).rstrip("/")
SECRET_PREFIX = os.getenv("DRIVE9_SECRET_PREFIX", "drive9/agentcore").rstrip("/")
CONTROL_METHOD_REQUESTED = os.getenv("AGENTCORE_CONTROL_METHOD", "auto").strip().lower()
AWS_CLI = os.getenv("AWS_CLI_BIN", "aws").strip() or "aws"
AUTHZ_DISCOVERY_URL = required("AUTHZ_DISCOVERY_URL")
AUTHZ_ALLOWED_AUDIENCES = csv_env("AUTHZ_ALLOWED_AUDIENCES")
AUTHZ_ALLOWED_CLIENTS = csv_env("AUTHZ_ALLOWED_CLIENTS")
AUTHZ_ALLOWED_JWT_ALGORITHMS = csv_env("AUTHZ_ALLOWED_JWT_ALGORITHMS") or ["RS256"]
AUTHZ_READ_SCOPE = os.getenv("AUTHZ_READ_SCOPE", "drive9.read").strip()
AUTHZ_WRITE_SCOPE = os.getenv("AUTHZ_WRITE_SCOPE", "drive9.write").strip()
AUTHZ_OPERATOR_SCOPE = os.getenv("AUTHZ_OPERATOR_SCOPE", "drive9.operator").strip()
AUTHZ_ADMIN_SCOPE = os.getenv("AUTHZ_ADMIN_SCOPE", "drive9.admin").strip()
AUTHZ_ALLOWED_SCOPES = [
    AUTHZ_READ_SCOPE,
    AUTHZ_WRITE_SCOPE,
    AUTHZ_OPERATOR_SCOPE,
    AUTHZ_ADMIN_SCOPE,
]

if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", REGION):
    raise RuntimeError(f"AWS_REGION is invalid: {REGION!r}")
if OPERATING_SYSTEM != "LINUX_ARM64":
    raise RuntimeError("OPERATING_SYSTEM is fixed to LINUX_ARM64 for this project")
if not SUBNETS or not SECURITY_GROUPS:
    raise RuntimeError("SUBNET_IDS and SECURITY_GROUP_IDS must each contain at least one ID")
if PROVIDER_MAX_LIFETIME <= 0 or PROVIDER_IDLE_TIMEOUT <= 0:
    raise RuntimeError("provider lifetime and idle timeout must be positive seconds")
if RUNTIME_MAX_LIFETIME <= 0 or RUNTIME_IDLE_TIMEOUT <= 0:
    raise RuntimeError("runtime lifetime and idle timeout must be positive seconds")
if RUNTIME_MAX_LIFETIME > PROVIDER_MAX_LIFETIME:
    raise RuntimeError("RUNTIME_MAX_LIFETIME must be <= PROVIDER_MAX_LIFETIME")
if VOLUME_SIZE_GIB <= 0:
    raise RuntimeError("CAPACITY_PROVIDER_VOLUME_SIZE_GIB must be positive")
if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", CAPACITY_PROVIDER_NAME):
    raise RuntimeError("CAPACITY_PROVIDER_NAME must match [A-Za-z][A-Za-z0-9_]{0,47}")
for _legacy in ("AGENT_RUNTIME_ROLE_ARN", "CAPACITY_PROVIDER_VOLUME_NAME"):
    if os.getenv(_legacy, "").strip():
        raise RuntimeError(
            f"{_legacy} is no longer supported because it shares one resource between tenants; "
            f"set {_legacy}_AGENT_A, {_legacy}_AGENT_B and {_legacy}_AGENT_C instead"
        )
# Per-tenant execution role, EBS volume and Secret. Missing or duplicated
# bindings fail here, before any AWS call.
TENANTS: dict[str, TenantResources] = load_tenant_resources(
    secret_prefix=SECRET_PREFIX, test_run_id=TEST_RUN_ID
)
if CONTROL_METHOD_REQUESTED not in {"auto", "sdk", "cli"}:
    raise RuntimeError("AGENTCORE_CONTROL_METHOD must be auto, sdk, or cli")
if not re.fullmatch(r"https://.+/\.well-known/openid-configuration", AUTHZ_DISCOVERY_URL):
    raise RuntimeError(
        "AUTHZ_DISCOVERY_URL must be an HTTPS OpenID Connect discovery URL ending in "
        "'/.well-known/openid-configuration'"
    )
if not AUTHZ_ALLOWED_AUDIENCES and not AUTHZ_ALLOWED_CLIENTS:
    raise RuntimeError("AUTHZ_ALLOWED_AUDIENCES or AUTHZ_ALLOWED_CLIENTS must be configured")
if any(not re.fullmatch(r"[!-~]{1,256}", scope) for scope in AUTHZ_ALLOWED_SCOPES):
    raise RuntimeError("authorization scopes must be non-empty printable ASCII without whitespace")
if len(set(AUTHZ_ALLOWED_SCOPES)) != len(AUTHZ_ALLOWED_SCOPES):
    raise RuntimeError("read, write, operator, and admin scopes must be distinct")
if any(algorithm not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
       for algorithm in AUTHZ_ALLOWED_JWT_ALGORITHMS):
    raise RuntimeError("AUTHZ_ALLOWED_JWT_ALGORITHMS contains an unsupported algorithm")
for remote_path, variable in (
    (DRIVE9_SHARED_BASE_REMOTE, "DRIVE9_SHARED_BASE_REMOTE"),
    (DRIVE9_AGENT_C_BASE_REMOTE, "DRIVE9_AGENT_C_BASE_REMOTE"),
):
    if not remote_path.startswith(":/") or ".." in remote_path.split("/"):
        raise RuntimeError(f"{variable} must be an absolute Drive9 path without '..'")


def _sdk_client() -> Any | None:
    if boto3 is None:
        return None
    return boto3.client("bedrock-agentcore-control", region_name=REGION)


control = _sdk_client()
SDK_OPERATIONS = {
    "create_capacity_provider",
    "get_capacity_provider",
    "delete_capacity_provider",
    "create_agent_runtime",
    "get_agent_runtime",
    "delete_agent_runtime",
}
SDK_SUPPORTED = control is not None and all(hasattr(control, method) for method in SDK_OPERATIONS)

if CONTROL_METHOD_REQUESTED == "sdk" and not SDK_SUPPORTED:
    raise RuntimeError(
        "boto3 does not expose the required Runtime Instances operations. "
        "Install a current boto3/botocore or use AGENTCORE_CONTROL_METHOD=cli."
    )
if CONTROL_METHOD_REQUESTED == "cli" and shutil.which(AWS_CLI) is None:
    raise RuntimeError(f"AWS CLI executable not found: {AWS_CLI}")
CONTROL_METHOD = "sdk" if CONTROL_METHOD_REQUESTED == "sdk" or (CONTROL_METHOD_REQUESTED == "auto" and SDK_SUPPORTED) else "cli"
if CONTROL_METHOD == "cli" and shutil.which(AWS_CLI) is None:
    raise RuntimeError(f"AWS CLI executable not found: {AWS_CLI}")


def _camel_to_kebab(value: str) -> str:
    # boto3 operation names use snake_case while AWS CLI uses kebab-case.
    value = value.replace("_", "-")
    return re.sub(r"(?<!^)(?=[A-Z])", "-", value).lower()


def _cli_call(operation: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    command = [AWS_CLI, "bedrock-agentcore-control", operation]
    if payload is not None:
        command.extend(["--cli-input-json", json.dumps(payload, separators=(",", ":"))])
    command.extend(["--region", REGION, "--output", "json", "--no-cli-pager"])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"AWS CLI {operation} failed: {detail[-4000:]}")
    if not result.stdout.strip():
        return {}
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"AWS CLI {operation} returned non-JSON output") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"AWS CLI {operation} returned a non-object response")
    return value


def _call(operation: str, **kwargs: Any) -> dict[str, Any]:
    if CONTROL_METHOD == "sdk":
        assert control is not None
        return getattr(control, operation)(**kwargs)
    return _cli_call(_camel_to_kebab(operation), kwargs)


def _wait_capacity_provider(capacity_provider_id: str, timeout: int = 1800) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = _call("get_capacity_provider", capacityProviderId=capacity_provider_id)
        status = current.get("status", "UNKNOWN")
        print(f"capacity provider {capacity_provider_id}: {status}", flush=True)
        if status in {"READY", "ACTIVE"}:
            return current
        if status in {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}:
            raise RuntimeError(json.dumps(current, default=str, indent=2))
        time.sleep(15)
    raise TimeoutError(f"capacity provider {capacity_provider_id} did not become READY")


def _wait_runtime(runtime_id: str, timeout: int = 1800) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = _call("get_agent_runtime", agentRuntimeId=runtime_id)
        status = current.get("status", "UNKNOWN")
        print(f"runtime {runtime_id}: {status}", flush=True)
        if status == "READY":
            return current
        if status in {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}:
            raise RuntimeError(json.dumps(current, default=str, indent=2))
        time.sleep(15)
    raise TimeoutError(f"runtime {runtime_id} did not become READY")


def _client_token(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}-{uuid.uuid4().hex}"[:256]


def _aws_call(service: str, operation: str, **kwargs: Any) -> dict[str, Any]:
    """Call a non-AgentCore AWS API through boto3 when present, else the CLI."""
    if boto3 is not None:
        return getattr(boto3.client(service, region_name=REGION), operation)(**kwargs)
    command = [AWS_CLI, service, _camel_to_kebab(operation)]
    command.extend(["--cli-input-json", json.dumps(kwargs, separators=(",", ":"))])
    command.extend(["--region", REGION, "--output", "json", "--no-cli-pager"])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"AWS CLI {service} {operation} failed: {detail[-4000:]}")
    value = json.loads(result.stdout or "{}")
    if not isinstance(value, dict):
        raise RuntimeError(f"AWS CLI {service} {operation} returned a non-object response")
    return value


def _verify_tenant_secret_isolation(tenants: dict[str, TenantResources]) -> dict[str, str]:
    """Fail unless each tenant role can read its own Secret and no other.

    Secret IDs are resolved to ARNs first so that two different IDs that name
    the same Secret are caught. Decisions come from iam:SimulatePrincipalPolicy
    against each role's identity policies.
    """
    secret_arns: dict[str, str] = {}
    for agent_id, tenant in tenants.items():
        described = _aws_call("secretsmanager", "describe_secret", SecretId=tenant.secret_id)
        arn = described.get("ARN")
        if not isinstance(arn, str) or not arn.startswith("arn:"):
            raise RuntimeError(f"could not resolve the Drive9 Secret ARN for {agent_id}")
        secret_arns[agent_id] = arn

    decisions: dict[tuple[str, str], str] = {}
    for tenant in tenants.values():
        marker: str | None = None
        while True:
            request: dict[str, Any] = {
                "PolicySourceArn": tenant.runtime_role_arn,
                "ActionNames": ["secretsmanager:GetSecretValue"],
                "ResourceArns": list(secret_arns.values()),
            }
            if marker:
                request["Marker"] = marker
            response = _aws_call("iam", "simulate_principal_policy", **request)
            for item in response.get("EvaluationResults", []):
                resource = item.get("EvalResourceName")
                decision = item.get("EvalDecision")
                if isinstance(resource, str) and isinstance(decision, str):
                    decisions[(tenant.runtime_role_arn, resource)] = decision
            if not response.get("IsTruncated"):
                break
            marker = response.get("Marker")

    validate_secret_access_decisions(tenants, secret_arns, decisions)
    print("tenant Secret isolation verified with iam:SimulatePrincipalPolicy", flush=True)
    return secret_arns


def _authorizer_configuration() -> dict[str, Any]:
    custom_authorizer: dict[str, Any] = {
        "discoveryUrl": AUTHZ_DISCOVERY_URL,
        "allowedScopes": AUTHZ_ALLOWED_SCOPES,
    }
    if AUTHZ_ALLOWED_AUDIENCES:
        custom_authorizer["allowedAudience"] = AUTHZ_ALLOWED_AUDIENCES
    if AUTHZ_ALLOWED_CLIENTS:
        custom_authorizer["allowedClients"] = AUTHZ_ALLOWED_CLIENTS
    return {"customJWTAuthorizer": custom_authorizer}


def _delete_runtime(runtime_id: str) -> None:
    try:
        _call("delete_agent_runtime", agentRuntimeId=runtime_id, clientToken=_client_token("delete-runtime"))
    except Exception as exc:  # Cleanup is best effort after a failed deployment.
        print(f"warning: could not delete runtime {runtime_id}: {exc}", file=sys.stderr)


def _delete_capacity_provider(capacity_provider_id: str) -> None:
    try:
        _call(
            "delete_capacity_provider",
            capacityProviderId=capacity_provider_id,
            clientToken=_client_token("delete-capacity"),
        )
    except Exception as exc:  # Cleanup is best effort after a failed deployment.
        print(f"warning: could not delete capacity provider {capacity_provider_id}: {exc}", file=sys.stderr)


def main() -> None:
    print(
        json.dumps(
            {
                "control_method": CONTROL_METHOD,
                "region": REGION,
                "operating_system": OPERATING_SYSTEM,
                "architecture": ARCHITECTURE,
                "instance_type": INSTANCE_TYPE,
                "drive9_server": DRIVE9_SERVER,
            },
            indent=2,
        ),
        flush=True,
    )

    capacity_provider_id = ""
    created_runtime_ids: list[str] = []
    # Runs before any resource is created: a shared or over-broad runtime
    # role aborts the deployment instead of producing a non-isolated one.
    secret_arns = _verify_tenant_secret_isolation(TENANTS)
    try:
        capacity = _call(
            "create_capacity_provider",
            name=CAPACITY_PROVIDER_NAME,
            description=f"{ARCHITECTURE} AgentCore Instances provider for Drive9 validation",
            permissionsConfiguration={
                "capacityProviderOperatorRoleArn": OPERATOR_ROLE_ARN,
            },
            clientToken=_client_token("create-capacity"),
            tags={
                "Project": "Drive9AgentCoreTest",
                "Architecture": ARCHITECTURE,
            },
            computeConfiguration={
                "ec2Configuration": {
                    "launchTemplateSource": {
                        "launchParameters": {
                            "operatingSystem": OPERATING_SYSTEM,
                            "instanceRequirements": {
                                "allowedInstanceTypes": [INSTANCE_TYPE],
                            },
                        }
                    },
                    "vpcConfiguration": {
                        "subnets": SUBNETS,
                        "securityGroups": SECURITY_GROUPS,
                    },
                    # One EBS volume per tenant; each runtime mounts only its own.
                    "volumes": [
                        {
                            "ebsConfiguration": {
                                "name": TENANTS[agent_id].volume_name,
                                "sizeGiB": VOLUME_SIZE_GIB,
                                "volumeType": "gp3",
                            }
                        }
                        for agent_id in AGENT_IDS
                    ],
                    "lifecycleConfiguration": {
                        "idleInstanceTimeout": PROVIDER_IDLE_TIMEOUT,
                        "maxLifetime": PROVIDER_MAX_LIFETIME,
                    },
                }
            },
        )
        capacity_provider_id = str(capacity["capacityProviderId"])
        capacity_provider_arn = str(capacity["capacityProviderArn"])
        _wait_capacity_provider(capacity_provider_id)

        runtime_suffix = re.sub(r"[^A-Za-z0-9_]", "_", TEST_RUN_ID)[-16:]
        agent_specs = [
            (f"drive9_agent_a_{runtime_suffix}", "agent-a"),
            (f"drive9_agent_b_{runtime_suffix}", "agent-b"),
            (f"drive9_agent_c_{runtime_suffix}", "agent-c"),
        ]
        runtime_results: dict[str, dict[str, Any]] = {}
        for runtime_name, agent_id in agent_specs:
            tenant = TENANTS[agent_id]
            response = _call(
                "create_agent_runtime",
                agentRuntimeName=runtime_name,
                description=f"Drive9 validation runtime for {agent_id}",
                roleArn=tenant.runtime_role_arn,
                authorizerConfiguration=_authorizer_configuration(),
                requestHeaderConfiguration={"requestHeaderAllowlist": ["Authorization"]},
                clientToken=_client_token(f"create-{agent_id}"),
                agentRuntimeArtifact={
                    "containerConfiguration": {
                        "containerUri": IMAGE_URI,
                    }
                },
                capacityProviderConfiguration={
                    "capacityProviderArn": capacity_provider_arn,
                },
                filesystemConfigurations=[
                    {
                        "capacityProviderVolume": {
                            "volumeName": tenant.volume_name,
                            "mountPath": "/mnt/scratch",
                        }
                    }
                ],
                lifecycleConfiguration={
                    "idleRuntimeSessionTimeout": RUNTIME_IDLE_TIMEOUT,
                    "maxLifetime": RUNTIME_MAX_LIFETIME,
                },
                protocolConfiguration={"serverProtocol": "HTTP"},
                environmentVariables={
                    "AGENT_ID": agent_id,
                    "DRIVE9_SECRET_ID": tenant.secret_id,
                    "DRIVE9_SERVER": DRIVE9_SERVER,
                    "DRIVE9_SHARED_BASE_REMOTE": DRIVE9_SHARED_BASE_REMOTE,
                    "DRIVE9_AGENT_C_BASE_REMOTE": DRIVE9_AGENT_C_BASE_REMOTE,
                    "EXPECTED_ARCHITECTURE": ARCHITECTURE,
                    "TEST_RUN_ID": TEST_RUN_ID,
                    "AUTHZ_DISCOVERY_URL": AUTHZ_DISCOVERY_URL,
                    "AUTHZ_ALLOWED_AUDIENCES": ",".join(AUTHZ_ALLOWED_AUDIENCES),
                    "AUTHZ_ALLOWED_CLIENTS": ",".join(AUTHZ_ALLOWED_CLIENTS),
                    "AUTHZ_ALLOWED_JWT_ALGORITHMS": ",".join(AUTHZ_ALLOWED_JWT_ALGORITHMS),
                    "AUTHZ_READ_SCOPE": AUTHZ_READ_SCOPE,
                    "AUTHZ_WRITE_SCOPE": AUTHZ_WRITE_SCOPE,
                    "AUTHZ_OPERATOR_SCOPE": AUTHZ_OPERATOR_SCOPE,
                    "AUTHZ_ADMIN_SCOPE": AUTHZ_ADMIN_SCOPE,
                },
                tags={
                    "Project": "Drive9AgentCoreTest",
                    "Architecture": ARCHITECTURE,
                    "AgentId": agent_id,
                },
            )
            runtime_id = str(response["agentRuntimeId"])
            created_runtime_ids.append(runtime_id)
            ready = _wait_runtime(runtime_id)
            runtime_results[agent_id] = {
                "agent_runtime_id": ready["agentRuntimeId"],
                "agent_runtime_arn": ready["agentRuntimeArn"],
                "version": ready["agentRuntimeVersion"],
                "secret_id": tenant.secret_id,
                "secret_arn": secret_arns[agent_id],
                "runtime_role_arn": tenant.runtime_role_arn,
                "capacity_provider_volume": tenant.volume_name,
            }

        deployment = {
            "region": REGION,
            "architecture": ARCHITECTURE,
            "operating_system": OPERATING_SYSTEM,
            "instance_type": INSTANCE_TYPE,
            "image_uri": IMAGE_URI,
            "drive9_server": DRIVE9_SERVER,
            "shared_base_remote": DRIVE9_SHARED_BASE_REMOTE,
            "agent_c_base_remote": DRIVE9_AGENT_C_BASE_REMOTE,
            "test_run_id": TEST_RUN_ID,
            "inbound_authorization": {
                "type": "CUSTOM_JWT",
                "discovery_url": AUTHZ_DISCOVERY_URL,
                "allowed_audiences": AUTHZ_ALLOWED_AUDIENCES,
                "allowed_clients": AUTHZ_ALLOWED_CLIENTS,
                "action_scopes": {
                    "read": AUTHZ_READ_SCOPE,
                    "write": AUTHZ_WRITE_SCOPE,
                    "operator": AUTHZ_OPERATOR_SCOPE,
                    "admin": AUTHZ_ADMIN_SCOPE,
                },
            },
            "control_method": CONTROL_METHOD,
            "capacity_provider_id": capacity_provider_id,
            "capacity_provider_arn": capacity_provider_arn,
            "runtimes": runtime_results,
        }
        Path("deployment.json").write_text(json.dumps(deployment, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(deployment, indent=2), flush=True)
    except Exception:
        for runtime_id in reversed(created_runtime_ids):
            _delete_runtime(runtime_id)
        if capacity_provider_id:
            _delete_capacity_provider(capacity_provider_id)
        raise


if __name__ == "__main__":
    main()
