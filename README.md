# Drive9 + AWS Bedrock AgentCore Runtime Instances (ARM64)

This demo deploys three AgentCore Runtime instances in AWS `us-east-2` to verify Drive9 CLI/API file operations, persistence, cross-agent handoff, permissions, and retrieval capabilities within the Runtime. Docker images and the Capacity Provider are pinned to ARM64; this project does not run CPU benchmarks or CPU quota tests.

## Verified Conclusions

- EC2, AWS CLI, and the AgentCore Runtime Instances API are located in `us-east-2`.
- The ARM64 Capacity Provider uses `LINUX_ARM64`, with the default instance type `c6g.large`.
- The Drive9 CLI successfully completed file read/write using the `DRIVE9_API_KEY` bearer token; the Runtime must not pass this token to `drive9 ctx import`.
- This test uses the Anonymous workspace `[https://api.drive9.ai](https://api.drive9.ai)`. Do not mix `api.drive9.ai` tokens with regional TiDBCloud servers.
- An older Runtime failed to start due to a `SyntaxError: '(' was never closed` in the image; the ARM64 image must be rebuilt and pushed before acceptance.
- agent-a and agent-b must use the same read-write scoped token and only access the shared directory; agent-c must use a separate read-only scoped token and its own directory, and verify that it cannot list the A/B shared directory.

## Files

- `app.py`: Runtime handler; reads the Drive9 token from Secrets Manager and executes CLI actions.
- `deploy.py`: Creates the ARM64 Capacity Provider and three Runtimes, with SDK/CLI control plane support.
- `tests/invoke_action.py`: Single-action invocation, supports `--method auto|sdk|cli`.
- `tests/run_tests.py`: SDK regression tests and Markdown/JSONL evidence output.
- `scripts/create_capacity_provider_operator_role.sh`: Creates the Capacity Provider Operator Role using the AWS CLI.
- `docs/EXECUTE_TESTS.md`: Complete execution, acceptance, cleanup, and troubleshooting steps.

## Quick Start


```bash
export AWS_REGION=us-east-2
export DRIVE9_SERVER=[https://api.drive9.ai](https://api.drive9.ai)
python3 -m py_compile app.py deploy.py tests/invoke_action.py tests/run_tests.py
```

Then follow [`docs/EXECUTE_TESTS.md`](docs/EXECUTE_TESTS.md) to build the `linux/arm64` image, push it to ECR, create the Secret, deploy the Runtimes, and run smoke and regression tests.

