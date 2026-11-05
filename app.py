"""Deterministic Drive9 validation agent for AgentCore Runtime Instances.

The handler exposes explicit actions so test outcomes do not depend on model
reasoning. All user-supplied paths are relative to the current test run root.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import boto3
import jwt
from jwt import PyJWKClient

try:
    # bedrock-agentcore >= 1.0 exports the runtime app at the package root.
    from bedrock_agentcore import BedrockAgentCoreApp
except ImportError:  # pragma: no cover - compatibility with early SDK builds
    from bedrock_agentcore.runtime import BedrockAgentCoreApp


app = BedrockAgentCoreApp()
LOGGER = logging.getLogger(__name__)


def _env_list(name: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in os.getenv(name, "").split(",") if value.strip())

AGENT_ID = os.getenv("AGENT_ID", "agent-unknown")
SECRET_ID = os.getenv("DRIVE9_SECRET_ID", "")
TEST_RUN_ID = os.getenv("TEST_RUN_ID", "local-test")
DRIVE9_SERVER = os.getenv("DRIVE9_SERVER", "https://api.drive9.ai")
EXPECTED_ARCHITECTURE = os.getenv("EXPECTED_ARCHITECTURE", "arm64").lower()
SHARED_BASE_REMOTE = os.getenv(
    "DRIVE9_SHARED_BASE_REMOTE", f":/agentcore-tests/{TEST_RUN_ID}/shared"
).rstrip("/")
AGENT_C_BASE_REMOTE = os.getenv(
    "DRIVE9_AGENT_C_BASE_REMOTE", f":/agentcore-tests/{TEST_RUN_ID}/agent-c"
).rstrip("/")
BASE_REMOTE = SHARED_BASE_REMOTE if AGENT_ID in {"agent-a", "agent-b"} else AGENT_C_BASE_REMOTE
for remote_path, variable in (
    (SHARED_BASE_REMOTE, "DRIVE9_SHARED_BASE_REMOTE"),
    (AGENT_C_BASE_REMOTE, "DRIVE9_AGENT_C_BASE_REMOTE"),
):
    if not remote_path.startswith(":/") or ".." in PurePosixPath(remote_path[2:]).parts:
        raise RuntimeError(f"{variable} must be an absolute Drive9 path without '..'")
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "1048576"))

# The Drive9 credential is only ever materialised as a 0600 context file in a
# private tmpfs directory. It is never placed in a child-process environment
# or command line, and it is re-read from Secrets Manager periodically so a
# rotated Secret takes effect without restarting the runtime.
DRIVE9_MEMORY_ROOT = Path("/dev/shm")
DRIVE9_SECRET_REFRESH_SECONDS = int(os.getenv("DRIVE9_SECRET_REFRESH_SECONDS", "900"))
if not 60 <= DRIVE9_SECRET_REFRESH_SECONDS <= 86400:
    raise RuntimeError("DRIVE9_SECRET_REFRESH_SECONDS must be between 60 and 86400")
_CHILD_PATH = "/usr/local/bin:/usr/bin:/bin"
# Plaintext credential variables are not a supported input. Remove them so no
# child process can inherit them, even one started with the default env.
for _plaintext_credential in ("DRIVE9_API_KEY", "DRIVE9_TEST_TOKEN", "DRIVE9_VAULT_TOKEN"):
    if os.environ.pop(_plaintext_credential, None) is not None:
        LOGGER.warning("ignoring plaintext credential variable %s; use DRIVE9_SECRET_ID", _plaintext_credential)

# AgentCore validates the same token at the service boundary. The application
# verifies it again before using any claim for per-action authorization so a
# forwarded or locally injected header cannot become a trusted role assertion.
AUTHZ_DISCOVERY_URL = os.getenv("AUTHZ_DISCOVERY_URL", "").strip()
AUTHZ_ALLOWED_AUDIENCES = _env_list("AUTHZ_ALLOWED_AUDIENCES")
AUTHZ_ALLOWED_CLIENTS = _env_list("AUTHZ_ALLOWED_CLIENTS")
AUTHZ_ALLOWED_JWT_ALGORITHMS = _env_list("AUTHZ_ALLOWED_JWT_ALGORITHMS") or ("RS256",)
AUTHZ_READ_SCOPE = os.getenv("AUTHZ_READ_SCOPE", "drive9.read").strip()
AUTHZ_WRITE_SCOPE = os.getenv("AUTHZ_WRITE_SCOPE", "drive9.write").strip()
AUTHZ_OPERATOR_SCOPE = os.getenv("AUTHZ_OPERATOR_SCOPE", "drive9.operator").strip()
AUTHZ_ADMIN_SCOPE = os.getenv("AUTHZ_ADMIN_SCOPE", "drive9.admin").strip()
# Least-privilege / isolation policy for each runtime identity. It is part of
# the image, not request input or deployment configuration, so neither a
# caller nor a deployer can relax the expectation that permission_test and
# visibility_test grade against. Unknown identities fail closed.
ISOLATION_POLICY: dict[str, dict[str, bool]] = {
    "agent-a": {"write_allowed": True, "shared_visible": True},
    "agent-b": {"write_allowed": True, "shared_visible": True},
    "agent-c": {"write_allowed": False, "shared_visible": False},
}
_FAIL_CLOSED_POLICY = {"write_allowed": False, "shared_visible": False}


def _isolation_policy() -> dict[str, bool]:
    return ISOLATION_POLICY.get(AGENT_ID, _FAIL_CLOSED_POLICY)

if not re.fullmatch(r"https://.+/\.well-known/openid-configuration", AUTHZ_DISCOVERY_URL):
    raise RuntimeError(
        "AUTHZ_DISCOVERY_URL must be an HTTPS OpenID Connect discovery URL ending in "
        "'/.well-known/openid-configuration'"
    )
if not AUTHZ_ALLOWED_AUDIENCES and not AUTHZ_ALLOWED_CLIENTS:
    raise RuntimeError("AUTHZ_ALLOWED_AUDIENCES or AUTHZ_ALLOWED_CLIENTS must be configured")
if any(not re.fullmatch(r"[!-~]{1,256}", scope) for scope in (
    AUTHZ_READ_SCOPE,
    AUTHZ_WRITE_SCOPE,
    AUTHZ_OPERATOR_SCOPE,
    AUTHZ_ADMIN_SCOPE,
)):
    raise RuntimeError("authorization scopes must be non-empty printable ASCII without whitespace")
if len({AUTHZ_READ_SCOPE, AUTHZ_WRITE_SCOPE, AUTHZ_OPERATOR_SCOPE, AUTHZ_ADMIN_SCOPE}) != 4:
    raise RuntimeError("read, write, operator, and admin scopes must be distinct")
if any(algorithm not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
       for algorithm in AUTHZ_ALLOWED_JWT_ALGORITHMS):
    raise RuntimeError("AUTHZ_ALLOWED_JWT_ALGORITHMS contains an unsupported algorithm")

_CONTEXT_LOCK = threading.Lock()
_CONTEXT_READY = False
_CONTEXT_NAME = ""
_SECRET_TOKEN = ""
_SECRET_SERVER = ""
_SECRET_LOADED_AT = 0.0
# Every token value seen by this process, so output is still redacted after
# a rotation replaces _SECRET_TOKEN.
_REDACTED_VALUES: set[str] = set()


class AuthorizationError(Exception):
    """Raised when a request cannot be authenticated or authorized."""


@dataclass(frozen=True)
class AuthorizedCaller:
    subject: str
    caller_id: str
    scopes: frozenset[str]


@lru_cache(maxsize=1)
def _openid_configuration() -> tuple[str, str]:
    request = Request(
        AUTHZ_DISCOVERY_URL,
        headers={"Accept": "application/json", "User-Agent": "drive9-agentcore-authorizer/1"},
    )
    try:
        with urlopen(request, timeout=5) as response:
            raw = response.read(65537)
    except Exception as exc:
        raise AuthorizationError("OIDC discovery is unavailable") from exc
    if len(raw) > 65536:
        raise AuthorizationError("OIDC discovery response is too large")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("OIDC discovery returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise AuthorizationError("OIDC discovery returned an invalid document")
    issuer = document.get("issuer")
    jwks_uri = document.get("jwks_uri")
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        raise AuthorizationError("OIDC discovery did not provide a valid HTTPS issuer")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
        raise AuthorizationError("OIDC discovery did not provide a valid HTTPS JWKS URI")
    return issuer.rstrip("/"), jwks_uri


@lru_cache(maxsize=4)
def _jwk_client(jwks_uri: str) -> PyJWKClient:
    return PyJWKClient(jwks_uri, cache_keys=True, cache_jwk_set=True, lifespan=300, timeout=5)


def _request_headers(context: Any) -> dict[str, str]:
    raw_headers = getattr(context, "request_headers", None)
    if not isinstance(raw_headers, dict):
        return {}
    return {
        str(name).strip().lower(): str(value).strip()
        for name, value in raw_headers.items()
        if isinstance(name, str) and isinstance(value, str)
    }


def _token_scopes(claims: dict[str, Any]) -> frozenset[str]:
    scopes: set[str] = set()
    for name in ("scope", "scp"):
        value = claims.get(name)
        if isinstance(value, str):
            scopes.update(item for item in value.split() if item)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            scopes.update(value)
    return frozenset(scopes)


def _authenticate_request(context: Any) -> AuthorizedCaller:
    authorization = _request_headers(context).get("authorization", "")
    match = re.fullmatch(r"Bearer ([A-Za-z0-9_\-.]+)", authorization)
    if match is None or len(match.group(1)) > 16384:
        raise AuthorizationError("a valid bearer token is required")
    token = match.group(1)
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise AuthorizationError("the bearer token header is invalid") from exc
    algorithm = header.get("alg")
    if algorithm not in AUTHZ_ALLOWED_JWT_ALGORITHMS:
        raise AuthorizationError("the bearer token algorithm is not allowed")

    issuer, jwks_uri = _openid_configuration()
    try:
        signing_key = _jwk_client(jwks_uri).get_signing_key_from_jwt(token)
        decode_options = {
            "require": ["exp", "iat", "sub"],
            "verify_aud": bool(AUTHZ_ALLOWED_AUDIENCES),
        }
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(AUTHZ_ALLOWED_JWT_ALGORITHMS),
            audience=list(AUTHZ_ALLOWED_AUDIENCES) or None,
            issuer=issuer,
            leeway=30,
            options=decode_options,
        )
    except jwt.PyJWTError as exc:
        raise AuthorizationError("the bearer token could not be verified") from exc

    client_id = claims.get("client_id", claims.get("azp"))
    if AUTHZ_ALLOWED_CLIENTS and client_id not in AUTHZ_ALLOWED_CLIENTS:
        raise AuthorizationError("the bearer token client is not allowed")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not re.fullmatch(r"[^\x00-\x1f\x7f]{1,256}", subject):
        raise AuthorizationError("the bearer token subject is invalid")
    scopes = _token_scopes(claims)
    caller_id = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:16]
    return AuthorizedCaller(subject=subject, caller_id=caller_id, scopes=scopes)


def _redact(value: str) -> str:
    for secret in sorted(_REDACTED_VALUES, key=len, reverse=True):
        value = value.replace(secret, "***REDACTED***")
    return value


def _passthrough_env() -> dict[str, str]:
    # Network/TLS settings only; nothing here grants authority.
    names = ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "TZ")
    return {name: os.environ[name] for name in names if os.environ.get(name)}


def _base_child_env() -> dict[str, str]:
    """Environment for first-party diagnostics: no AWS or Drive9 credentials."""
    return {
        **_passthrough_env(),
        "PATH": _CHILD_PATH,
        "HOME": tempfile.gettempdir(),
        "LANG": "C.UTF-8",
    }


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout: int = 120,
    process_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            # Never fall back to inheriting os.environ: it carries the
            # AgentCore container-credential variables.
            env=_base_child_env() if env is None else env,
            check=False,
            **(process_options or {}),
        )
        return {
            "command": args[0:3],
            "exit_code": proc.returncode,
            "stdout": _redact(proc.stdout[:MAX_RESPONSE_BYTES]),
            "stderr": _redact(proc.stderr[:MAX_RESPONSE_BYTES]),
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": args[0:3],
            "exit_code": 124,
            "stdout": _redact((exc.stdout or "")[:MAX_RESPONSE_BYTES]),
            "stderr": "command timed out",
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    except FileNotFoundError as exc:
        return {
            "command": args[0:3],
            "exit_code": 127,
            "stdout": "",
            "stderr": str(exc),
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def _drive9_env() -> dict[str, str]:
    """Explicit allowlist environment for the drive9 CLI.

    The parent environment is deliberately not copied: it contains the
    AgentCore/AWS container-credential variables, which the vendor binary has
    no use for. The Drive9 token is not passed here either; the CLI reads it
    from the private context file written by _write_drive9_context().
    """
    return {
        **_passthrough_env(),
        "PATH": _CHILD_PATH,
        "HOME": str(_drive9_memory_home()),
        "XDG_CACHE_HOME": str(_drive9_cache_dir()),
        "TMPDIR": tempfile.gettempdir(),
        "LANG": "C.UTF-8",
        "DRIVE9_SERVER": _SECRET_SERVER or DRIVE9_SERVER,
        "DRIVE9_CLI_LOG_ENABLED": "false",
    }


def _drive9_memory_home() -> Path:
    """tmpfs HOME that holds only this runtime's Drive9 context file."""
    return DRIVE9_MEMORY_ROOT / f"drive9-home-{AGENT_ID}"


def _drive9_cache_dir() -> Path:
    # Keep CLI/FUSE caches off the size-limited tmpfs that holds the context.
    return Path(tempfile.gettempdir()) / f"drive9-cache-{AGENT_ID}"


def _ensure_private_dir(path: Path) -> None:
    """Create or accept a 0700 directory owned by this uid; never a symlink."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing to use non-directory credential path: {path}")
    if info.st_uid != os.geteuid():
        raise RuntimeError(f"refusing to use credential directory owned by another user: {path}")
    if stat.S_IMODE(info.st_mode) != 0o700:
        os.chmod(path, 0o700)


def _write_drive9_context(token: str, server: str) -> None:
    """Atomically write the Drive9 CLI context as a 0600 file on tmpfs."""
    if not DRIVE9_MEMORY_ROOT.is_dir():
        raise RuntimeError(f"{DRIVE9_MEMORY_ROOT} is required to hold the Drive9 context in memory")
    home = _drive9_memory_home()
    config_dir = home / ".drive9"
    _ensure_private_dir(home)
    _ensure_private_dir(config_dir)
    cache_dir = _drive9_cache_dir()
    _ensure_private_dir(cache_dir)
    # The FUSE layer derives its cache from $HOME/.cache; point that at the
    # private on-disk cache instead of filling tmpfs.
    home_cache = home / ".cache"
    if not os.path.lexists(home_cache):
        os.symlink(cache_dir, home_cache)
    elif not home_cache.is_symlink() or os.readlink(home_cache) != str(cache_dir):
        raise RuntimeError("refusing to use an unexpected Drive9 cache path")
    document = {
        "server": server,
        "current_context": AGENT_ID,
        # The bearer token from `drive9 token issue --print` is the same
        # credential the CLI previously took from DRIVE9_API_KEY, which it
        # classifies as an owner-kind API key.
        "contexts": {AGENT_ID: {"type": "owner", "server": server, "api_key": token}},
    }
    temporary = config_dir / f".config-{uuid.uuid4().hex}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, config_dir / "config")
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _remove_drive9_context() -> None:
    try:
        (_drive9_memory_home() / ".drive9" / "config").unlink(missing_ok=True)
    except OSError:
        pass


atexit.register(_remove_drive9_context)


def _secret_is_fresh() -> bool:
    return bool(_SECRET_TOKEN) and (
        time.monotonic() - _SECRET_LOADED_AT < DRIVE9_SECRET_REFRESH_SECONDS
    )


def _load_secret_token(*, force: bool = False) -> str:
    """Read the tenant's Drive9 token from Secrets Manager.

    The cached value expires after DRIVE9_SECRET_REFRESH_SECONDS so that a
    rotated or revoked Secret is picked up by a long-lived runtime.
    """
    global _SECRET_TOKEN, _SECRET_SERVER, _SECRET_LOADED_AT
    if not force and _secret_is_fresh():
        return _SECRET_TOKEN
    if not SECRET_ID:
        raise RuntimeError(
            "DRIVE9_SECRET_ID is required; plaintext token environment variables are not supported"
        )

    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=SECRET_ID)
    value = response["SecretString"]
    parsed: Any = None
    server = ""
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            token = parsed.get("token", parsed.get("api_key"))
        else:
            token = value
        if isinstance(parsed, dict) and parsed.get("server"):
            server = str(parsed["server"]).rstrip("/")
    except (json.JSONDecodeError, KeyError, TypeError):
        token = value
    if not token:
        if isinstance(parsed, dict) and ("token" in parsed or "api_key" in parsed):
            raise RuntimeError("Drive9 secret token is empty")
        raise RuntimeError("Drive9 secret JSON must contain token or api_key")
    token = str(token).strip()
    if not token:
        raise RuntimeError("Drive9 token is empty")
    if server and not re.fullmatch(r"https://[^\s/]+(/[^\s]*)?", server):
        raise RuntimeError("Drive9 secret server must be an HTTPS URL")
    _REDACTED_VALUES.add(token)
    _SECRET_TOKEN = token
    _SECRET_SERVER = server
    _SECRET_LOADED_AT = time.monotonic()
    return _SECRET_TOKEN


def _context_names(output: str) -> list[str]:
    """Extract context names from the CLI's JSON output across CLI versions."""
    try:
        value: Any = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(value, dict):
        value = value.get("contexts", value.get("items", value))
        if isinstance(value, dict):
            for key in ("name", "context", "contextName"):
                if isinstance(value.get(key), str):
                    return [value[key]]
            # Some CLI releases emit a name -> metadata mapping.
            return [name for name in value if isinstance(name, str)]
    if isinstance(value, dict):
        value = list(value.values())
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for item in value:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            for key in ("name", "context", "contextName"):
                if isinstance(item.get(key), str):
                    names.append(item[key])
                    break
    return names


def _context_status() -> dict[str, Any]:
    return {
        "status": "ready",
        "agent_id": AGENT_ID,
        "context": _CONTEXT_NAME,
        "credential_source": "tmpfs-context",
        "server": _SECRET_SERVER or DRIVE9_SERVER,
    }


def _ensure_context() -> dict[str, Any]:
    global _CONTEXT_READY, _CONTEXT_NAME
    with _CONTEXT_LOCK:
        if _CONTEXT_READY and _secret_is_fresh():
            return _context_status()

        # First use, or the cached token has expired: re-read the Secret and
        # rewrite the context so rotation and revocation take effect. A
        # failed refresh fails closed instead of reusing the stale token.
        _CONTEXT_READY = False
        try:
            token = _load_secret_token(force=True)
        except Exception:
            _remove_drive9_context()
            raise
        _write_drive9_context(token, _SECRET_SERVER or DRIVE9_SERVER)
        probe = _run(["drive9", "fs", "ls", BASE_REMOTE], env=_drive9_env())
        if probe["exit_code"] != 0:
            raise RuntimeError(f"Drive9 credential/workspace probe failed: {probe['stderr']}")
        _CONTEXT_NAME = AGENT_ID
        _CONTEXT_READY = True
        return _context_status()


def _safe_component(value: str, field: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
        raise ValueError(f"invalid {field}")
    return value


def _reject_git_metadata(parts: tuple[str, ...]) -> None:
    # Git executes command strings from repository-local config and hooks
    # (core.fsmonitor, filter drivers, hooks). The file actions must never be
    # able to create or modify a .git directory that git_prepare/git_verify
    # will later operate on. Compare case-insensitively so that ".GIT" cannot
    # slip through on case-insensitive backends.
    if any(part.casefold() == ".git" for part in parts):
        raise ValueError("paths containing a '.git' component are not allowed")


def _remote(relative: str | None = None) -> str:
    if relative in (None, "", "."):
        return BASE_REMOTE
    raw = str(relative)
    # Request paths are always relative to this runtime's tenant root. Drive9's
    # `:/` syntax is an absolute remote path, so accepting it here would let a
    # caller discard BASE_REMOTE and address another agent or test run. Absolute
    # paths are reserved for trusted, server-owned probes that do not use this
    # request-path resolver.
    if raw.startswith(":/"):
        raise ValueError("path must be relative to the agent root; ':/...' is not allowed")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("path must be relative and cannot contain '..'")
    _reject_git_metadata(path.parts)
    normalized = "/".join(part for part in path.parts if part not in ("", "."))
    if not normalized:
        return BASE_REMOTE
    return f"{BASE_REMOTE}/{normalized}"


def _write_text(relative: str, content: str, *, append: bool = False) -> dict[str, Any]:
    _ensure_context()
    env = _drive9_env()
    destination = _remote(relative)
    if append:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(content)
            local_path = handle.name
        try:
            result = _run(
                ["drive9", "fs", "cp", "--append", local_path, destination],
                env=env,
            )
        finally:
            Path(local_path).unlink(missing_ok=True)
    else:
        result = _run(
            ["drive9", "fs", "cp", "-", destination],
            env=env,
            input_text=content,
        )
    result.update(
        {
            "path": destination,
            "size": len(content.encode("utf-8")),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
    )
    return result


def _read_text(relative: str) -> dict[str, Any]:
    _ensure_context()
    result = _run(["drive9", "fs", "cat", _remote(relative)], env=_drive9_env())
    if result["exit_code"] == 0:
        raw = result["stdout"].encode("utf-8")
        result.update({"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return result


def _architecture_matches(observed: str) -> bool:
    """Compare uname output using the names exposed by Linux and AgentCore."""
    normalized = observed.lower().strip()
    expected = EXPECTED_ARCHITECTURE.replace("linux_", "").replace("linux/", "")
    if expected in {"arm64", "aarch64"}:
        return normalized in {"arm64", "aarch64"}
    return normalized == expected


def action_preflight(_: dict[str, Any]) -> dict[str, Any]:
    context_error = None
    try:
        context = _ensure_context()
    except Exception as exc:  # returned as evidence for environment diagnosis
        context = None
        context_error = str(exc)
    env = _drive9_env()
    checks = {
        "uname": _run(["uname", "-a"]),
        "architecture": _run(["uname", "-m"]),
        "identity": _run(["id"]),
        "drive9_version": _run(["drive9", "--version"], env=env),
        "dns": _run(
            [
                "getent",
                "hosts",
                urlparse(_SECRET_SERVER or DRIVE9_SERVER).hostname or "api.drive9.ai",
            ]
        ),
        "https": _run(
            [
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                _SECRET_SERVER or DRIVE9_SERVER,
            ],
            timeout=30,
        ),
        "context": _run(["drive9", "ctx", "show", "--json"], env=env),
        "workspace_list": _run(["drive9", "fs", "ls", BASE_REMOTE], env=env),
        "fuse_filesystems": _run(["sh", "-c", "grep -i fuse /proc/filesystems || true"]),
        "capabilities": _run(["capsh", "--print"]),
        "drive9_fuse_doctor": _run(["drive9", "doctor", "fuse"], env=env),
    }
    # Bearer-token authentication intentionally does not require a local
    # delegated context. `ctx show` remains diagnostic only.
    required_checks = ("drive9_version", "dns", "https", "workspace_list")
    https_code = checks["https"]["stdout"].strip()
    checks_ok = all(checks[name]["exit_code"] == 0 for name in required_checks)
    checks_ok = checks_ok and bool(re.fullmatch(r"[1-5][0-9][0-9]", https_code))
    return {
        "status": "PASS"
        if context_error is None
        and _architecture_matches(checks["architecture"]["stdout"].strip())
        and checks_ok
        else "FAIL",
        "agent_id": AGENT_ID,
        "test_run_id": TEST_RUN_ID,
        "expected_architecture": EXPECTED_ARCHITECTURE,
        "python_architecture": platform.machine(),
        "dev_fuse_exists": Path("/dev/fuse").exists(),
        "context_init": context,
        "context_error": context_error,
        "checks": checks,
    }


def action_write(payload: dict[str, Any]) -> dict[str, Any]:
    result = _write_text(str(payload["path"]), str(payload.get("content", "")))
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_read(payload: dict[str, Any]) -> dict[str, Any]:
    result = _read_text(str(payload["path"]))
    expected = payload.get("expected_content")
    content_match = expected is None or result.get("stdout") == str(expected)
    return {
        "status": "PASS" if result["exit_code"] == 0 and content_match else "FAIL",
        "content_match": content_match,
        "result": result,
    }


def action_append(payload: dict[str, Any]) -> dict[str, Any]:
    result = _write_text(str(payload["path"]), str(payload.get("content", "")), append=True)
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_list(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    result = _run(["drive9", "fs", "ls", "-l", _remote(payload.get("path", "."))], env=_drive9_env())
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_stat(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    result = _run(["drive9", "fs", "stat", "-o", "json", _remote(str(payload["path"]))], env=_drive9_env())
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_move(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    result = _run(
        ["drive9", "fs", "mv", _remote(str(payload["source"])), _remote(str(payload["destination"]))],
        env=_drive9_env(),
    )
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_copy(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    result = _run(
        ["drive9", "fs", "cp", _remote(str(payload["source"])), _remote(str(payload["destination"]))],
        env=_drive9_env(),
    )
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_delete(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    result = _run(["drive9", "fs", "rm", _remote(str(payload["path"]))], env=_drive9_env())
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_find(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    args = ["drive9", "fs", "find", _remote(payload.get("path", "."))]
    for key, flag in (("name", "-name"), ("newer", "-newer"), ("older", "-older"), ("size", "-size")):
        if payload.get(key) is not None:
            args.extend([flag, str(payload[key])])
    tags = payload.get("tag", [])
    if isinstance(tags, str):
        tags = [tags]
    for tag in tags:
        args.extend(["-tag", str(tag)])
    result = _run(args, env=_drive9_env())
    return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "result": result}


def action_search(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    query = str(payload["query"])
    result = _run(
        ["drive9", "fs", "grep", "--json", query, _remote(payload.get("path", "."))],
        env=_drive9_env(),
        timeout=180,
    )
    if result["exit_code"] != 0:
        fallback = _run(
            ["drive9", "fs", "grep", query, _remote(payload.get("path", "."))],
            env=_drive9_env(),
            timeout=180,
        )
        result["fallback"] = fallback
        if fallback["exit_code"] == 0:
            return {"status": "PASS", "result": result}
    return {"status": "PASS" if result["exit_code"] == 0 else "FEATURE_UNAVAILABLE", "result": result}


def action_handoff_prepare(payload: dict[str, Any]) -> dict[str, Any]:
    task_id = _safe_component(str(payload.get("task_id", "task-001")), "task_id")
    state = {
        "task_id": task_id,
        "producer_agent": AGENT_ID,
        "stage": payload.get("stage", "code-modified"),
        "git_branch": payload.get("git_branch", "feature/drive9-test"),
        "test_status": payload.get("test_status", "not-run"),
        "next_action": payload.get("next_action", "continue validation"),
        "checkpoint_id": str(uuid.uuid4()),
        "created_at": time.time(),
    }
    relative = f"handoff/{task_id}/state.json"
    result = _write_text(relative, json.dumps(state, ensure_ascii=False, indent=2))
    return {
        "status": "PASS" if result["exit_code"] == 0 else "FAIL",
        "handoff_path": relative,
        "state": state,
        "result": result,
    }


def action_handoff_continue(payload: dict[str, Any]) -> dict[str, Any]:
    task_id = _safe_component(str(payload.get("task_id", "task-001")), "task_id")
    state_path = f"handoff/{task_id}/state.json"
    source = _read_text(state_path)
    if source["exit_code"] != 0:
        return {"status": "FAIL", "read_state": source}
    state = json.loads(source["stdout"])
    continuation = {
        "task_id": task_id,
        "consumer_agent": AGENT_ID,
        "source_checkpoint_id": state.get("checkpoint_id"),
        "source_agent": state.get("producer_agent"),
        "result": payload.get("result", "task continued successfully"),
        "completed_at": time.time(),
    }
    result_path = f"handoff/{task_id}/result-{AGENT_ID}.json"
    write = _write_text(result_path, json.dumps(continuation, ensure_ascii=False, indent=2))
    return {
        "status": "PASS" if write["exit_code"] == 0 else "FAIL",
        "source_state": state,
        "result_path": result_path,
        "write_result": write,
    }


def action_permission_test(_: dict[str, Any]) -> dict[str, Any]:
    # The payload is deliberately ignored: the expected outcome comes from
    # the built-in policy for this runtime identity only.
    _ensure_context()
    expect_write = _isolation_policy()["write_allowed"]
    probe = f"permissions/{AGENT_ID}-probe.txt"
    write = _write_text(probe, f"permission probe from {AGENT_ID}\n")
    write_allowed = write["exit_code"] == 0
    delete = None
    if write_allowed:
        delete = _run(["drive9", "fs", "rm", _remote(probe)], env=_drive9_env())
    outside = _run(
        ["drive9", "fs", "cat", ":/agentcore-tests/outside-scope-probe.txt"],
        env=_drive9_env(),
    )
    outside_denied = outside["exit_code"] != 0
    passed = write_allowed == expect_write and outside_denied
    return {
        "status": "PASS" if passed else "FAIL",
        "policy_source": "built-in",
        "expected_write_allowed": expect_write,
        "actual_write_allowed": write_allowed,
        "actual_outside_scope_denied": outside_denied,
        "write": write,
        "delete": delete,
        "outside_scope_read": outside,
    }


def action_visibility_test(_: dict[str, Any]) -> dict[str, Any]:
    _ensure_context()
    # Both the probe target and expected outcome are deployment policy. A
    # caller must not be able to choose a different path or expected result
    # and thereby steer the least-privilege verdict.
    target = SHARED_BASE_REMOTE
    expect_visible = _isolation_policy()["shared_visible"]
    result = _run(["drive9", "fs", "ls", "-l", target], env=_drive9_env())
    visible = result["exit_code"] == 0
    passed = visible == expect_visible
    return {
        "status": "PASS" if passed else "FAIL",
        "policy_source": "built-in",
        "target": target,
        "expected_visible": expect_visible,
        "actual_visible": visible,
        "result": result,
    }


def _mounted(callback: Callable[[Path], dict[str, Any]]) -> dict[str, Any]:
    _ensure_context()
    env = _drive9_env()
    mountpoint = Path(f"/mnt/drive9-{AGENT_ID}")
    try:
        mountpoint.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # AgentCore may make the image filesystem read-only or deny writes to
        # /mnt even when the process runs as root. Treat that as a platform
        # capability limitation, matching the /dev/fuse handling below.
        if exc.errno in {1, 13, 30}:  # EPERM, EACCES, EROFS
            return {
                "status": "PLATFORM_BLOCKED",
                "dev_fuse_exists": Path("/dev/fuse").exists(),
                "mount_log": str(exc),
            }
        raise
    log_path = Path(f"/tmp/drive9-mount-{AGENT_ID}.log")

    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [
                "drive9",
                "mount",
                "--direct-mount-strict",
                "--supervise-foreground",
                "--debug",
                BASE_REMOTE,
                str(mountpoint),
            ],
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )

        healthy = False
        health: dict[str, Any] | None = None
        for _ in range(30):
            if process.poll() is not None:
                break
            health = _run(["drive9", "mount", "health", str(mountpoint)], env=env, timeout=5)
            if health["exit_code"] == 0:
                healthy = True
                break
            time.sleep(1)

        if not healthy:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            log_handle.flush()
            log_text = log_path.read_text(encoding="utf-8", errors="replace")[-MAX_RESPONSE_BYTES:]
            reason = "PLATFORM_BLOCKED" if not Path("/dev/fuse").exists() or "operation not permitted" in log_text.lower() else "FAIL"
            return {
                "status": reason,
                "dev_fuse_exists": Path("/dev/fuse").exists(),
                "health": health,
                "mount_log": _redact(log_text),
            }

        try:
            callback_result = callback(mountpoint)
            return {
                "status": "PASS",
                "health": health,
                "callback": callback_result,
            }
        finally:
            _run(["drive9", "mount", "drain", "--timeout", "60s", str(mountpoint)], env=env, timeout=75)
            _run(["drive9", "umount", str(mountpoint)], env=env, timeout=30)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()


def action_mount_test(_: dict[str, Any]) -> dict[str, Any]:
    marker = f"mount test from {AGENT_ID} at {time.time()}\n"

    def callback(mountpoint: Path) -> dict[str, Any]:
        target = mountpoint / f"mount-test-{AGENT_ID}.txt"
        _write_regular_file(target, marker, fsync=True)
        remote_read = _read_text(target.name)
        return {
            "local_sha256": hashlib.sha256(marker.encode("utf-8")).hexdigest(),
            "remote_read": remote_read,
            "match": remote_read.get("stdout") == marker,
        }

    result = _mounted(callback)
    if result["status"] == "PASS" and not result["callback"]["match"]:
        result["status"] = "FAIL"
    return result


# Git never runs against Drive9. The shared Drive9 tree (including any
# .git/config, hooks or .gitattributes on it) is writable by every holder of
# the A/B token, and git honours many command-executing keys from repository
# config (core.fsmonitor, filter.*, diff.textconv, alias.*, ...). Validating
# that config in a separate process cannot close the race with the later git
# run. Instead, git_prepare builds the repository in a fresh private
# directory on this tenant's own volume, runs git there as an unprivileged
# uid, and publishes only a plain JSON snapshot. git_verify parses that JSON
# against a fixed schema and never runs git on remote content.
GIT_STAGING_ROOT = Path("/mnt/scratch/git-staging")
GIT_UID = 10000
GIT_GID = 10000
GIT_SNAPSHOT_SCHEMA = "drive9-git-snapshot/v1"
_GIT_SNAPSHOT_FIELDS = (
    "schema",
    "task_id",
    "producer_agent",
    "branch",
    "head",
    "status",
    "log",
    "dirty_content",
    "created_at",
)
_GIT_SNAPSHOT_MAX_TEXT = 65536

# Command-line config has the highest precedence. The staging repository is
# created by this process, so nothing untrusted can set these keys; the
# overrides are defence in depth against system/global config.
_GIT_HARDENING = (
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.attributesFile=/dev/null",
    "core.pager=cat",
    "core.editor=false",
    "sequence.editor=false",
    "core.sshCommand=false",
    "core.untrackedCache=false",
    "credential.helper=",
    "protocol.allow=never",
    "commit.gpgSign=false",
    "tag.gpgSign=false",
    "submodule.recurse=false",
    "init.templateDir=",
    "init.defaultBranch=main",
    "user.email=agentcore@example.invalid",
    "user.name=AgentCore Test",
)


def _git_env() -> dict[str, str]:
    """Minimal environment for git: no Drive9 token, no AWS credentials."""
    return {
        "PATH": "/usr/bin:/bin",
        # Never read: GIT_CONFIG_GLOBAL replaces $HOME/.gitconfig.
        "HOME": str(GIT_STAGING_ROOT),
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CEILING_DIRECTORIES": str(GIT_STAGING_ROOT),
    }


def _git_process_options() -> dict[str, Any]:
    """Drop to the unprivileged image user if the runtime runs as root."""
    if os.geteuid() == 0:
        return {"user": GIT_UID, "group": GIT_GID, "extra_groups": []}
    return {}


def _chown_for_git(path: Path) -> None:
    if os.geteuid() == 0:
        os.chown(path, GIT_UID, GIT_GID, follow_symlinks=False)


def _git_staging_root() -> Path:
    """Create or accept the tenant-local staging root; refuse symlinks."""
    root = GIT_STAGING_ROOT
    if root.is_symlink():
        raise RuntimeError("refusing to use a symlinked Git staging root")
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(root)
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError("refusing to use a symlinked Git staging root")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("Git staging root is not a directory")
    allowed_owners = {os.geteuid(), GIT_UID} if os.geteuid() == 0 else {os.geteuid()}
    if info.st_uid not in allowed_owners:
        raise RuntimeError("Git staging root is owned by another user")
    _chown_for_git(root)
    os.chmod(root, 0o700)
    return root


def _run_local_git(repo: Path, *args: str, timeout: int = 60) -> dict[str, Any]:
    """Run git against a private local repository created by this process."""
    command = ["git"]
    for override in _GIT_HARDENING:
        command.extend(["-c", override])
    # Explicit --git-dir/--work-tree disables repository discovery.
    command.extend(["--git-dir", str(repo / ".git"), "--work-tree", str(repo), *args])
    result = _run(
        command,
        env=_git_env(),
        timeout=timeout,
        process_options=_git_process_options(),
    )
    result["command"] = ["git", *args[:2]]
    if result["exit_code"] != 0:
        raise RuntimeError(f"git {args[0]} failed: {result['stderr'][-2000:]}")
    return result


def _write_regular_file(path: Path, content: str, *, fsync: bool = False) -> None:
    """Write a file without following a planted symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise RuntimeError(f"refusing to write non-regular file: {path.name}")
        handle.write(content)
        handle.flush()
        if fsync:
            os.fsync(handle.fileno())


def _git_snapshot_path(task_id: str) -> str:
    return f"git-workspaces/{task_id}/snapshot.json"


def _validate_git_snapshot(raw: str, task_id: str) -> dict[str, Any]:
    """Parse a remote snapshot as data only; anything unexpected is rejected."""
    try:
        snapshot = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Git snapshot has an invalid schema: not JSON") from exc
    if not isinstance(snapshot, dict) or set(snapshot) != set(_GIT_SNAPSHOT_FIELDS):
        raise RuntimeError("Git snapshot has an invalid schema: unexpected fields")
    if snapshot["schema"] != GIT_SNAPSHOT_SCHEMA:
        raise RuntimeError("Git snapshot has an invalid schema: unknown version")
    for field in _GIT_SNAPSHOT_FIELDS:
        if field == "created_at":
            continue
        value = snapshot[field]
        if not isinstance(value, str) or len(value) > _GIT_SNAPSHOT_MAX_TEXT:
            raise RuntimeError(f"Git snapshot has an invalid schema: bad {field}")
    if not isinstance(snapshot["created_at"], (int, float)) or isinstance(snapshot["created_at"], bool):
        raise RuntimeError("Git snapshot has an invalid schema: bad created_at")
    if snapshot["task_id"] != task_id:
        raise RuntimeError("Git snapshot has an invalid schema: task_id mismatch")
    if snapshot["producer_agent"] not in ISOLATION_POLICY:
        raise RuntimeError("Git snapshot has an invalid schema: unknown producer_agent")
    if snapshot["branch"] != f"feature/{task_id}":
        raise RuntimeError("Git snapshot has an invalid schema: unexpected branch")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", snapshot["head"]):
        raise RuntimeError("Git snapshot has an invalid schema: bad head")
    return snapshot


def action_git_prepare(payload: dict[str, Any]) -> dict[str, Any]:
    task_id = _safe_component(str(payload.get("task_id", "git-001")), "task_id")
    root = _git_staging_root()
    repo = Path(tempfile.mkdtemp(prefix=f"{task_id}-", dir=root))
    try:
        _chown_for_git(repo)
        _run_local_git(repo, "init", "--quiet")
        _write_regular_file(repo / "README.md", "# Drive9 Git workspace test\n")
        _run_local_git(repo, "add", "--", "README.md")
        _run_local_git(repo, "commit", "--quiet", "--no-verify", "-m", "base commit")
        _run_local_git(repo, "checkout", "--quiet", "-B", f"feature/{task_id}")
        dirty_content = f"uncommitted work from {AGENT_ID}\n"
        _write_regular_file(repo / "dirty.txt", dirty_content)
        snapshot = {
            "schema": GIT_SNAPSHOT_SCHEMA,
            "task_id": task_id,
            "producer_agent": AGENT_ID,
            "branch": _run_local_git(repo, "branch", "--show-current")["stdout"].strip(),
            "head": _run_local_git(repo, "rev-parse", "HEAD")["stdout"].strip(),
            "status": _run_local_git(repo, "status", "--porcelain=v1")["stdout"],
            "log": _run_local_git(repo, "log", "-1", "--oneline")["stdout"].strip(),
            "dirty_content": dirty_content,
            "created_at": time.time(),
        }
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    snapshot_path = _git_snapshot_path(task_id)
    publish = _write_text(snapshot_path, json.dumps(snapshot, ensure_ascii=False, indent=2))
    return {
        "status": "PASS" if publish["exit_code"] == 0 else "FAIL",
        "execution": "tenant-local-unprivileged",
        "snapshot_path": snapshot_path,
        "snapshot": snapshot,
        "publish": publish,
    }


def action_git_verify(payload: dict[str, Any]) -> dict[str, Any]:
    task_id = _safe_component(str(payload.get("task_id", "git-001")), "task_id")
    snapshot_path = _git_snapshot_path(task_id)
    source = _read_text(snapshot_path)
    if source["exit_code"] != 0:
        return {
            "status": "FAIL",
            "execution": "no-git-on-remote-content",
            "snapshot_path": snapshot_path,
            "read_snapshot": source,
        }
    snapshot = _validate_git_snapshot(source["stdout"], task_id)
    return {
        "status": "PASS",
        "execution": "no-git-on-remote-content",
        "snapshot_path": snapshot_path,
        "source_agent": snapshot["producer_agent"],
        "branch": snapshot["branch"],
        "head": snapshot["head"],
        "status_porcelain": snapshot["status"],
        "dirty_content": snapshot["dirty_content"],
    }


ACTIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "preflight": action_preflight,
    "write": action_write,
    "read": action_read,
    "append": action_append,
    "list": action_list,
    "stat": action_stat,
    "move": action_move,
    "copy": action_copy,
    "delete": action_delete,
    "find": action_find,
    "search": action_search,
    "handoff_prepare": action_handoff_prepare,
    "handoff_continue": action_handoff_continue,
    "permission_test": action_permission_test,
    "visibility_test": action_visibility_test,
    "mount_test": action_mount_test,
    "git_prepare": action_git_prepare,
    "git_verify": action_git_verify,
}

# Every action is assigned explicitly. Adding a new action without also
# choosing its required scope fails during startup instead of silently
# inheriting a permissive default.
ACTION_REQUIRED_SCOPE: dict[str, str] = {
    "read": AUTHZ_READ_SCOPE,
    "list": AUTHZ_READ_SCOPE,
    "stat": AUTHZ_READ_SCOPE,
    "find": AUTHZ_READ_SCOPE,
    "search": AUTHZ_READ_SCOPE,
    "write": AUTHZ_WRITE_SCOPE,
    "append": AUTHZ_WRITE_SCOPE,
    "copy": AUTHZ_WRITE_SCOPE,
    "move": AUTHZ_WRITE_SCOPE,
    "handoff_prepare": AUTHZ_WRITE_SCOPE,
    "handoff_continue": AUTHZ_WRITE_SCOPE,
    "preflight": AUTHZ_OPERATOR_SCOPE,
    "delete": AUTHZ_OPERATOR_SCOPE,
    "permission_test": AUTHZ_OPERATOR_SCOPE,
    "visibility_test": AUTHZ_OPERATOR_SCOPE,
    "mount_test": AUTHZ_ADMIN_SCOPE,
    "git_prepare": AUTHZ_ADMIN_SCOPE,
    "git_verify": AUTHZ_ADMIN_SCOPE,
}
if ACTIONS.keys() != ACTION_REQUIRED_SCOPE.keys():
    missing = sorted(ACTIONS.keys() - ACTION_REQUIRED_SCOPE.keys())
    stale = sorted(ACTION_REQUIRED_SCOPE.keys() - ACTIONS.keys())
    raise RuntimeError(f"action authorization matrix mismatch; missing={missing}, stale={stale}")

_SCOPES_GRANTING_REQUIRED_SCOPE: dict[str, frozenset[str]] = {
    AUTHZ_READ_SCOPE: frozenset(
        {AUTHZ_READ_SCOPE, AUTHZ_WRITE_SCOPE, AUTHZ_OPERATOR_SCOPE, AUTHZ_ADMIN_SCOPE}
    ),
    AUTHZ_WRITE_SCOPE: frozenset({AUTHZ_WRITE_SCOPE, AUTHZ_OPERATOR_SCOPE, AUTHZ_ADMIN_SCOPE}),
    AUTHZ_OPERATOR_SCOPE: frozenset({AUTHZ_OPERATOR_SCOPE, AUTHZ_ADMIN_SCOPE}),
    AUTHZ_ADMIN_SCOPE: frozenset({AUTHZ_ADMIN_SCOPE}),
}


def _authorize_action(caller: AuthorizedCaller, action: str) -> str:
    required_scope = ACTION_REQUIRED_SCOPE.get(action)
    if required_scope is None:
        raise AuthorizationError("unknown action")
    if caller.scopes.isdisjoint(_SCOPES_GRANTING_REQUIRED_SCOPE[required_scope]):
        raise AuthorizationError("the caller is not authorized for this action")
    return required_scope


def _denied(action: str, started: float, caller_id: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "DENIED",
        "error_code": "ACCESS_DENIED",
        "error": "request is not authorized",
        "action": action,
        "agent_id": AGENT_ID,
        "test_run_id": TEST_RUN_ID,
        "started_at_epoch": started,
        "finished_at_epoch": time.time(),
    }
    if caller_id is not None:
        result["caller_id"] = caller_id
    return result


@app.entrypoint
def handle_request(payload: dict[str, Any], context: Any | None = None) -> dict[str, Any]:
    started = time.time()
    action = str(payload.get("action", "")) if isinstance(payload, dict) else ""
    try:
        caller = _authenticate_request(context)
    except AuthorizationError as exc:
        LOGGER.warning("authorization denied action=%r reason=%s", action[:64], exc)
        return _denied(action, started)
    if action not in ACTIONS:
        return {
            "status": "FAIL",
            "error_code": "UNKNOWN_ACTION",
            "error": "unknown action",
            "action": action,
            "agent_id": AGENT_ID,
            "test_run_id": TEST_RUN_ID,
            "caller_id": caller.caller_id,
            "started_at_epoch": started,
            "finished_at_epoch": time.time(),
        }
    try:
        required_scope = _authorize_action(caller, action)
    except AuthorizationError as exc:
        LOGGER.warning(
            "authorization denied caller_id=%s action=%r reason=%s",
            caller.caller_id,
            action,
            exc,
        )
        return _denied(action, started, caller.caller_id)
    LOGGER.info(
        "authorization allowed caller_id=%s action=%s required_scope=%s",
        caller.caller_id,
        action,
        required_scope,
    )
    try:
        result = ACTIONS[action](payload)
    except Exception as exc:
        result = {"status": "FAIL", "error": _redact(str(exc))}
    result.update(
        {
            "action": action,
            "agent_id": AGENT_ID,
            "test_run_id": TEST_RUN_ID,
            "caller_id": caller.caller_id,
            "authorized_scope": required_scope,
            "started_at_epoch": started,
            "finished_at_epoch": time.time(),
        }
    )
    return result


if __name__ == "__main__":
    app.run()
