"""Minimal OAuth client for JWT-authorized AgentCore runtimes."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def bearer_token(environment_name: str = "AGENTCORE_BEARER_TOKEN") -> str:
    token = os.getenv(environment_name, "").strip()
    if not token:
        raise RuntimeError(f"environment variable {environment_name} is required")
    if any(character.isspace() for character in token):
        raise RuntimeError(f"environment variable {environment_name} is not a valid bearer token")
    return token


def invoke_oauth(
    *,
    region: str,
    runtime_arn: str,
    session_id: str,
    payload: dict[str, Any],
    token: str,
    timeout: int = 300,
) -> dict[str, Any]:
    endpoint = os.getenv(
        "AGENTCORE_ENDPOINT_URL", f"https://bedrock-agentcore.{region}.amazonaws.com"
    ).rstrip("/")
    url = f"{endpoint}/runtimes/{quote(runtime_arn, safe='')}/invocations?qualifier=DEFAULT"
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:4000]
        raise RuntimeError(
            f"AgentCore OAuth invocation failed with HTTP {exc.code}: {detail}"
        ) from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AgentCore returned a non-JSON response") from exc
    if not isinstance(value, dict):
        raise RuntimeError("AgentCore returned a non-object JSON response")
    return value
