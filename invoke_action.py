"""Invoke one action on a deployed AgentCore runtime and print the full result."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import shutil
import tempfile
import uuid
import sys
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from runtime_oauth_client import bearer_token, invoke_oauth

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Invoke one app.py action through Bedrock AgentCore Runtime."
    )
    parser.add_argument("--deployment", default="deployment.json")
    parser.add_argument("--agent", required=True, choices=("agent-a", "agent-b", "agent-c"))
    parser.add_argument(
        "--method",
        choices=("oauth", "sdk", "cli", "auto"),
        default="oauth",
        help="AgentCore invocation method; JWT-authorized deployments require oauth (default).",
    )
    parser.add_argument(
        "--session-id",
        help="Reuse this value to stay in one AgentCore session; omitted means a new ID.",
    )
    payload = parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--payload", help="Action request as a JSON object string.")
    payload.add_argument("--payload-file", help="Path to a JSON action request file.")
    return parser.parse_args()


def load_payload(args: argparse.Namespace) -> dict[str, Any]:
    raw = (
        Path(args.payload_file).read_text(encoding="utf-8")
        if args.payload_file
        else args.payload
    )
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("payload must be a JSON object")
    if not value.get("action"):
        raise ValueError("payload must include a non-empty action")
    return value


def _decode_cli_response(value: Any) -> Any:
    """Decode AWS CLI blob output across CLI versions and output formats."""
    if isinstance(value, dict) and "response" in value:
        value = value["response"]
    if isinstance(value, dict) or isinstance(value, list):
        return value
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        return value
    for candidate in (raw,):
        try:
            return json.loads(candidate)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    try:
        decoded = base64.b64decode(raw, validate=True)
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            decoded_text = decoded.decode("utf-8")
            return decoded_text
    except (ValueError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def _invoke_sdk(deployment: dict[str, Any], runtime: dict[str, Any], session_id: str, payload: dict[str, Any]) -> Any:
    import boto3

    client = boto3.client("bedrock-agentcore", region_name=deployment["region"])
    response = client.invoke_agent_runtime(
        agentRuntimeArn=runtime["agent_runtime_arn"],
        runtimeSessionId=session_id,
        qualifier="DEFAULT",
        contentType="application/json",
        accept="application/json",
        payload=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    )
    raw_body = response["response"].read()
    try:
        return json.loads(raw_body)
    except json.JSONDecodeError:
        return raw_body.decode("utf-8", errors="replace")


def _invoke_cli(deployment: dict[str, Any], runtime: dict[str, Any], session_id: str, payload: dict[str, Any]) -> Any:
    aws_bin = shutil.which("aws")
    if not aws_bin:
        raise RuntimeError("AWS CLI executable not found")
    output_path = ""
    with tempfile.NamedTemporaryFile(prefix="agentcore-response-", delete=False) as output:
        output_path = output.name
    command = [
        aws_bin,
        "bedrock-agentcore",
        "invoke-agent-runtime",
        "--agent-runtime-arn",
        runtime["agent_runtime_arn"],
        "--runtime-session-id",
        session_id,
        "--qualifier",
        "DEFAULT",
        "--content-type",
        "application/json",
        "--accept",
        "application/json",
        "--payload",
        json.dumps(payload, ensure_ascii=False),
        "--region",
        deployment["region"],
        "--cli-binary-format",
        "raw-in-base64-out",
        output_path,
        "--output",
        "json",
        "--no-cli-pager",
    ]
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise RuntimeError(f"AWS CLI invoke-agent-runtime failed: {detail[-4000:]}")
        # New AWS CLI releases write the InvokeAgentRuntime response blob to
        # outfile; older releases may still return a JSON envelope on stdout.
        response_bytes = Path(output_path).read_bytes()
        if response_bytes:
            return _decode_cli_response(response_bytes)
        try:
            envelope: Any = json.loads(result.stdout)
        except json.JSONDecodeError:
            envelope = result.stdout
        return _decode_cli_response(envelope)
    finally:
        Path(output_path).unlink(missing_ok=True)


def main() -> None:
    args = parse_args()
    deployment = json.loads(Path(args.deployment).read_text(encoding="utf-8"))
    runtime = deployment["runtimes"][args.agent]
    session_id = args.session_id or f"{args.agent}-manual-{uuid.uuid4().hex}"
    payload = load_payload(args)

    method = args.method
    if method == "oauth":
        body = invoke_oauth(
            region=deployment["region"],
            runtime_arn=runtime["agent_runtime_arn"],
            session_id=session_id,
            payload=payload,
            token=bearer_token(),
        )
    elif method in {"auto", "sdk"}:
        try:
            body = _invoke_sdk(deployment, runtime, session_id, payload)
            method = "sdk"
        except Exception as exc:
            # Only fall back when the local SDK cannot expose the data-plane
            # service; invocation/authentication failures must remain visible.
            unsupported = isinstance(exc, (ImportError, AttributeError, NotImplementedError)) or exc.__class__.__name__ in {
                "UnknownServiceError",
                "UnknownEndpointError",
            }
            if args.method == "sdk" or not unsupported:
                raise
            body = _invoke_cli(deployment, runtime, session_id, payload)
            method = "cli"
    else:
        body = _invoke_cli(deployment, runtime, session_id, payload)

    print(
        json.dumps(
            {
                "agent": args.agent,
                "method": method,
                "session_id": session_id,
                "runtime_arn": runtime["agent_runtime_arn"],
                "request": payload,
                "response": body,
            },
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )
    if not isinstance(body, dict) or body.get("status") in {"FAIL", "DENIED"}:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
