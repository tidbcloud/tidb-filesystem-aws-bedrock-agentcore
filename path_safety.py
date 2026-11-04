"""Fail-closed path validation shared by the runtime and test harness."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath


_TEST_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_MAX_REMOTE_PATH_BYTES = 4096


def validate_test_run_id(test_run_id: object) -> str:
    """Validate and return a test-run identifier with no path components."""
    if not isinstance(test_run_id, str) or not _TEST_RUN_ID_PATTERN.fullmatch(test_run_id):
        raise ValueError(
            "test_run_id must be 1-128 ASCII letters, digits, dots, underscores, or hyphens "
            "and must start with a letter or digit"
        )
    return test_run_id


def safe_output_directory(output_root: str | Path, test_run_id: object) -> Path:
    """Return a test-run directory that is guaranteed to stay under output_root."""
    validated_test_run_id = validate_test_run_id(test_run_id)
    resolved_root = Path(output_root).expanduser().resolve()
    resolved_output = (resolved_root / validated_test_run_id).resolve()
    try:
        resolved_output.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("test_run_id resolves outside the output directory") from exc
    return resolved_output


def validate_drive9_base_remote(value: object, field: str = "BASE_REMOTE") -> str:
    """Validate a trusted Drive9 tenant root and return its canonical form."""
    if not isinstance(value, str) or not value.startswith(":/"):
        raise ValueError(f"{field} must be an absolute Drive9 path")
    remainder = value[2:]
    if not remainder or remainder.startswith("/"):
        raise ValueError(f"{field} must identify a non-root Drive9 prefix")
    _reject_unsafe_text(remainder, field)
    path = PurePosixPath(remainder)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} cannot contain an absolute or parent path")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        raise ValueError(f"{field} must identify a non-root Drive9 prefix")
    return ":/" + "/".join(parts)


def confine_drive9_path(
    base_remote: object,
    supplied_path: object | None,
    *,
    forbidden_components: tuple[str, ...] = (".git",),
) -> str:
    """Resolve a caller-relative path beneath a trusted Drive9 tenant root.

    Drive9's ``:/`` syntax is an absolute remote path. It is rejected rather
    than honoured or silently reinterpreted. Every successfully returned path
    is checked again to guarantee it is either the tenant root or its child.
    """
    base = validate_drive9_base_remote(base_remote)
    if supplied_path in (None, "", "."):
        return base
    if not isinstance(supplied_path, str):
        raise ValueError("path must be a string relative to the agent root")
    _reject_unsafe_text(supplied_path, "path")
    if supplied_path.startswith(":/"):
        raise ValueError("path must be relative to the agent root; ':/...' is not allowed")
    path = PurePosixPath(supplied_path)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("path must be relative and cannot contain '..'")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    forbidden = {component.casefold() for component in forbidden_components}
    for part in parts:
        if part.casefold() in forbidden:
            raise ValueError(f"path contains forbidden component {part.casefold()!r}")
    resolved = base if not parts else f"{base}/{'/'.join(parts)}"
    if resolved != base and not resolved.startswith(base + "/"):
        raise ValueError("path resolves outside the agent root")
    return resolved


def _reject_unsafe_text(value: str, field: str) -> None:
    if len(value.encode("utf-8")) > _MAX_REMOTE_PATH_BYTES:
        raise ValueError(f"{field} exceeds {_MAX_REMOTE_PATH_BYTES} bytes")
    if "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} contains an unsafe character")
