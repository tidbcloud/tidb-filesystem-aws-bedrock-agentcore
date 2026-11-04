"""Run Drive9 functional, persistence, permission, FUSE and Git tests."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from runtime_oauth_client import bearer_token, invoke_oauth
from path_safety import safe_output_directory, validate_test_run_id
from isolation_grading import HARNESS_ISOLATION_POLICY, grade_permission, grade_visibility


def load_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Drive9 AgentCore regression tests.")
    parser.add_argument("--deployment", default="deployment.json")
    parser.add_argument("--output", default="artifacts")
    parser.add_argument(
        "--skip-mount",
        action="store_true",
        help="Skip only the optional FUSE mount test; safe local Git tests still run.",
    )
    return parser.parse_args()


args = load_args()
deployment = json.loads(Path(args.deployment).read_text(encoding="utf-8"))
test_run_id = validate_test_run_id(deployment.get("test_run_id"))
output_dir = safe_output_directory(args.output, test_run_id)
output_dir.mkdir(parents=True, exist_ok=True)
jsonl_path = output_dir / "results.jsonl"
report_path = output_dir / "report.md"
sessions_path = output_dir / "sessions.json"

runtimes = {agent_id: value["agent_runtime_arn"] for agent_id, value in deployment["runtimes"].items()}
auth_token = bearer_token()
results: list[dict[str, Any]] = []


def new_session(agent_id: str, label: str) -> str:
    return f"{agent_id}-{label}-{uuid.uuid4().hex}"


Grader = Callable[[str, Dict[str, Any]], Tuple[str, Dict[str, Any]]]
SHARED_BASE_REMOTE = str(deployment["shared_base_remote"])


def grade_c_visibility(agent_id: str, body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    return grade_visibility(agent_id, body, expected_target=SHARED_BASE_REMOTE)


def invoke(
    agent_id: str,
    session_id: str,
    payload: dict[str, Any],
    test_id: str,
    grader: Grader | None = None,
) -> dict[str, Any]:
    started = time.time()
    try:
        body = invoke_oauth(
            region=deployment["region"],
            runtime_arn=runtimes[agent_id],
            session_id=session_id,
            payload=payload,
            token=auth_token,
        )
        status = body.get("status", "FAIL") if isinstance(body, dict) else "FAIL"
        error = None
    except Exception as exc:
        body = {}
        status = "FAIL"
        error = str(exc)
    grading = None
    if grader is not None:
        runtime_status = status
        if status in {"PASS", "FAIL"} and isinstance(body, dict):
            status, grading = grader(agent_id, body)
        else:
            grading = {}
        grading["runtime_reported_status"] = runtime_status
    record = {
        "test_id": test_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "action": payload.get("action"),
        "started_at": started,
        "finished_at": time.time(),
        "status": status,
        "error": error,
        "response": body,
    }
    if grading is not None:
        record["harness_grading"] = grading
    results.append(record)
    print(f"{test_id}: {status}", flush=True)
    return record


def listing_lines(record: dict[str, Any]) -> list[str]:
    response = record.get("response", {})
    result = response.get("result", {}) if isinstance(response, dict) else {}
    stdout = result.get("stdout", "") if isinstance(result, dict) else ""
    return sorted(line.strip() for line in str(stdout).splitlines() if line.strip())


def compare_shared_listing(path: str, agent_a: dict[str, Any], agent_b: dict[str, Any]) -> dict[str, Any]:
    a_entries = listing_lines(agent_a)
    b_entries = listing_lines(agent_b)
    listings_match = agent_a["status"] == "PASS" and agent_b["status"] == "PASS" and a_entries == b_entries
    record = {
        "test_id": "SHARED-AB-001",
        "agent_id": "agent-a+agent-b",
        "session_id": f"{agent_a['session_id']}|{agent_b['session_id']}",
        "action": "compare_shared_listing",
        "started_at": min(agent_a["started_at"], agent_b["started_at"]),
        "finished_at": max(agent_a["finished_at"], agent_b["finished_at"]),
        "status": "PASS" if listings_match else "FAIL",
        "error": None if listings_match else "agent-a and agent-b directory listings differ",
        "response": {
            "path": path,
            "listings_match": listings_match,
            "agent_a_entries": a_entries,
            "agent_b_entries": b_entries,
        },
    }
    results.append(record)
    print(f"SHARED-AB-001: {record['status']}", flush=True)
    print(json.dumps(record["response"], ensure_ascii=False, indent=2), flush=True)
    return record


sessions = {
    "agent-a": new_session("agent-a", "primary"),
    "agent-b": new_session("agent-b", "primary"),
    "agent-c": new_session("agent-c", "primary"),
}

# 1. Environment, architecture, connectivity and Drive9 workspace.
for agent_id in ("agent-a", "agent-b", "agent-c"):
    invoke(agent_id, sessions[agent_id], {"action": "preflight"}, f"ENV-{agent_id[-1].upper()}-001")

# 2. Basic CRUD and append.
initial = "Drive9 AgentCore ARM64 functional test\n"
expected = initial + "appended line\n"
invoke("agent-a", sessions["agent-a"], {"action": "write", "path": "functional/source.txt", "content": initial}, "FS-001")
invoke("agent-a", sessions["agent-a"], {"action": "read", "path": "functional/source.txt", "expected_content": initial}, "FS-002")
invoke("agent-a", sessions["agent-a"], {"action": "stat", "path": "functional/source.txt"}, "FS-003")
invoke("agent-a", sessions["agent-a"], {"action": "append", "path": "functional/source.txt", "content": "appended line\n"}, "FS-004")
invoke("agent-a", sessions["agent-a"], {"action": "copy", "source": "functional/source.txt", "destination": "functional/copied.txt"}, "FS-005")
invoke("agent-a", sessions["agent-a"], {"action": "move", "source": "functional/source.txt", "destination": "functional/moved.txt"}, "FS-006")
listing_a = invoke("agent-a", sessions["agent-a"], {"action": "list", "path": "functional"}, "SHARED-A-001")
listing_b = invoke("agent-b", sessions["agent-b"], {"action": "list", "path": "functional"}, "SHARED-B-001")
shared_listing = compare_shared_listing("functional", listing_a, listing_b)
c_visibility = invoke(
    "agent-c",
    sessions["agent-c"],
    {"action": "visibility_test"},
    "ISOLATION-C-001",
    grade_c_visibility,
)

# 3. Cross-runtime persistence.
invoke("agent-b", sessions["agent-b"], {"action": "read", "path": "functional/moved.txt", "expected_content": expected}, "PERSIST-001")

# 4. Multi-agent handoff.
invoke("agent-a", sessions["agent-a"], {"action": "handoff_prepare", "task_id": "task-001", "test_status": "functional checks running", "next_action": "continue validation"}, "MULTI-001")
invoke("agent-b", sessions["agent-b"], {"action": "handoff_continue", "task_id": "task-001", "result": "validation continued"}, "MULTI-002")
invoke("agent-a", sessions["agent-a"], {"action": "read", "path": "handoff/task-001/result-agent-b.json"}, "MULTI-003")

# 5. Least privilege.
invoke("agent-a", sessions["agent-a"], {"action": "permission_test"}, "AUTH-001", grade_permission)
invoke("agent-b", sessions["agent-b"], {"action": "permission_test"}, "AUTH-002", grade_permission)
invoke("agent-c", sessions["agent-c"], {"action": "permission_test"}, "AUTH-003", grade_permission)

# 6. Find and semantic search.
documents = {
    "search/retry.md": "The service uses exponential backoff to recover from connection timeouts.",
    "search/pricing.md": "The pricing plan separates storage, compute, and network transfer costs.",
    "search/security.md": "Scoped credentials enforce least privilege for each collaborating agent.",
}
for index, (path, content) in enumerate(documents.items(), start=1):
    invoke("agent-a", sessions["agent-a"], {"action": "write", "path": path, "content": content}, f"SEARCH-SEED-{index:03d}")
invoke("agent-b", sessions["agent-b"], {"action": "find", "path": "search", "name": "*.md"}, "SEARCH-001")
invoke("agent-b", sessions["agent-b"], {"action": "search", "path": "search", "query": "how does the code recover from transient network failures"}, "SEARCH-002")

# 7. FUSE is optional. Git runs unprivileged on tenant-local EBS and does not
# consume repository metadata from the Drive9 mount, so it is independent of FUSE.
if not args.skip_mount:
    invoke("agent-a", sessions["agent-a"], {"action": "mount_test"}, "FUSE-001")
invoke("agent-a", sessions["agent-a"], {"action": "git_prepare", "task_id": "git-001"}, "GIT-001")
invoke("agent-b", sessions["agent-b"], {"action": "git_verify", "task_id": "git-001"}, "GIT-002")

# 8. Fresh session recovery proves Drive9 persistence independently.
fresh_a_session = new_session("agent-a", "fresh-instance")
sessions["agent-a-fresh"] = fresh_a_session
invoke("agent-a", fresh_a_session, {"action": "read", "path": "functional/moved.txt", "expected_content": expected}, "PERSIST-002")
invoke("agent-a", fresh_a_session, {"action": "read", "path": "handoff/task-001/result-agent-b.json"}, "PERSIST-003")

sessions_path.write_text(json.dumps(sessions, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
with jsonl_path.open("w", encoding="utf-8") as handle:
    for record in results:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")

counts: dict[str, int] = {}
for record in results:
    counts[record["status"]] = counts.get(record["status"], 0) + 1
if counts.get("FAIL", 0) or counts.get("DENIED", 0):
    decision = "NO-GO"
elif counts.get("PLATFORM_BLOCKED", 0) or counts.get("FEATURE_UNAVAILABLE", 0):
    decision = "CONDITIONAL GO"
else:
    decision = "GO"

lines = [
    "# Drive9 on AWS Bedrock AgentCore Runtime Instances 测试报告", "",
    f"- Test Run ID: `{test_run_id}`", f"- Architecture: `{deployment['architecture']}`", f"- Instance Type: `{deployment['instance_type']}`", f"- Overall Decision: **{decision}**", "",
    "## 结果汇总", "", "| Status | Count |", "|---|---:|",
]
if args.skip_mount:
    lines.insert(5, "- FUSE test: **SKIPPED** (`--skip-mount`); safe local Git tests still executed")
for status, count in sorted(counts.items()):
    lines.append(f"| {status} | {count} |")
lines.extend(["", "## 用例明细", "", "| Test ID | Agent | Action | Status |", "|---|---|---|---|"])
for record in results:
    lines.append(f"| {record['test_id']} | {record['agent_id']} | {record['action']} | {record['status']} |")
lines.extend([
    "",
    "## Agent A/B 共享目录快照",
    "",
    f"- Path: `{shared_listing['response']['path']}`",
    f"- Listings match: **{str(shared_listing['response']['listings_match']).upper()}**",
    "",
    "### agent-a",
    "",
    "```text",
    *shared_listing["response"]["agent_a_entries"],
    "```",
    "",
    "### agent-b",
    "",
    "```text",
    *shared_listing["response"]["agent_b_entries"],
    "```",
    "",
    "## Agent C 目录隔离",
    "",
    f"- Target: `{c_visibility.get('harness_grading', {}).get('observed_target', 'unknown')}`",
    f"- Expected visible (harness policy): **{str(HARNESS_ISOLATION_POLICY['agent-c']['shared_visible']).upper()}**",
    f"- Observed visible: **{str(c_visibility.get('harness_grading', {}).get('observed_visible')).upper()}**",
    f"- Harness verdict: **{c_visibility['status']}** (runtime reported: {c_visibility.get('harness_grading', {}).get('runtime_reported_status')})",
    "- Agent-c must receive an inaccessible result (access denied or not found) when listing the A/B shared directory.",
])
lines.extend(["", "## 判定说明", "", "- `PLATFORM_BLOCKED`：AgentCore 未暴露 `/dev/fuse` 或拒绝 mount capability，不代表 Drive9 CLI/API 失败。", "- `FEATURE_UNAVAILABLE`：当前环境未开放相应 Drive9 检索能力。", "- 报告发布前应删除或散列 Runtime ARN、Session ID、AWS Account ID 等标识。"])
report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(json.dumps({"decision": decision, "counts": counts, "report": str(report_path), "jsonl": str(jsonl_path), "sessions": str(sessions_path)}, indent=2))
if decision == "NO-GO":
    raise SystemExit(1)
