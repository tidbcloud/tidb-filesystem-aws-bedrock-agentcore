# Drive9 + AgentCore 执行手册（ARM64）

以下命令在项目根目录执行，AWS Region 固定为 `us-east-2`。EC2 连接示例：

```bash
ssh -i awsagentcore.pem ec2-user@ec2-3-16-165-159.us-east-2.compute.amazonaws.com
```

## 1. 前置检查

准备 Python 3.10+、AWS CLI v2、Docker Buildx、`jq`、两个同 VPC 子网、安全组、AgentCore Operator Role、三个互不相同的 Runtime Execution Role、OIDC/OAuth provider，以及三个 Drive9 token。每个 Runtime Execution Role 的 trust policy 必须允许 `bedrock-agentcore.amazonaws.com` 承担；仅允许 `ec2.amazonaws.com` 会在 `create-agent-runtime` 时失败。安全组必须允许出站 TCP 443；如果使用私有子网，需要可经 NAT 访问 ECR、Secrets Manager、CloudWatch、OIDC discovery/JWKS 和 Drive9。

在 IdP/resource server 中配置四个 scope：`drive9.read`、`drive9.write`、`drive9.operator`、`drive9.admin`。用于完整回归和舞台 Demo 的短期 token 需要 `drive9.admin`；普通诊断调用只发 `drive9.read`，不要给它 write、delete、mount 或 Git 权限。

```bash
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=$AWS_REGION
aws sts get-caller-identity
python3 --version
aws --version
docker version
docker buildx version
```

本次测试使用 Anonymous workspace `https://api.drive9.ai`。如果使用 TiDBCloud server（例如 `https://aws-us-east-1.drive9.ai`），必须使用该 server 对应的 token，不能混用。

已完成的环境验证记录：EC2 可通过用户提供的 SSH 地址连接；AWS CLI `2.36.34` 已提供 `create-capacity-provider`、`create-agent-runtime` 和 `invoke-agent-runtime`；Drive9 CLI 使用 bearer token 已成功完成文件读写。若账号没有私有子网，可使用同 VPC 的可出站子网；本次账号实际使用一个 public subnet 完成验证。旧 Runtime 的失败日志为 `SyntaxError: '(' was never closed`，属于旧镜像语法错误，不能作为新 ARM64 镜像的验收结果。

### 创建 Capacity Provider Operator Role

本项目提供 [`scripts/create_capacity_provider_operator_role.sh`](../scripts/create_capacity_provider_operator_role.sh)，使用 AWS CLI 创建或更新 `CAPACITY_PROVIDER_OPERATOR_ROLE`。脚本绑定 AWS 官方托管策略 `BedrockAgentCoreRuntimeInstancesOperatorRolePolicy`，并将 trust policy 限制为当前账号在本 Region 创建的 Capacity Provider：

```bash
export AWS_REGION=us-east-2
export CAPACITY_PROVIDER_OPERATOR_ROLE_NAME=AgentCoreCapacityProviderOperatorRole
bash scripts/create_capacity_provider_operator_role.sh
```

脚本最后会打印 `CAPACITY_PROVIDER_OPERATOR_ROLE_ARN`，将该值用于部署：

```bash
export CAPACITY_PROVIDER_OPERATOR_ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/AgentCoreCapacityProviderOperatorRole
```

该 Role 只负责 Capacity Provider 管理的 EC2、Auto Scaling、EBS、网络接口、EventBridge 和相关 service-linked role 操作；不负责 Runtime 容器读取 Secrets Manager，也不负责调用 Runtime。Runtime Execution Role 需要单独配置，并允许 `bedrock-agentcore.amazonaws.com` 承担。

## 2. 创建 token 和 Secret

在已登录 Drive9 CLI 的环境生成 scoped token。A/B 共用共享目录权限，C 仅能访问自己的独立目录；C 不得拥有 A/B 共享目录的 `read` 或 `list` 权限：

```bash
export TEST_RUN_ID=agentcore-$(date -u +%Y%m%dT%H%M%SZ)
export DRIVE9_SERVER=https://api.drive9.ai
# A and B intentionally share one token and one directory.
drive9 token issue --subject "${TEST_RUN_ID}-agents-ab" --ttl 24h --allow /:pseudoroot --allow "/agentcore-tests/$TEST_RUN_ID/shared:read,list,search,write,delete" --print > agents-ab.token
# C has a separate read-only directory. Do not grant it the A/B shared prefix.
drive9 token issue --subject "${TEST_RUN_ID}-agent-c" --ttl 24h --allow /:pseudoroot --allow "/agentcore-tests/$TEST_RUN_ID/agent-c:read,list,search" --print > agent-c.token
cp agents-ab.token agent-a.token
cp agents-ab.token agent-b.token
for token_file in agents-ab.token agent-a.token agent-b.token agent-c.token; do
  test -s "$token_file" || { echo "empty token file: $token_file" >&2; exit 1; }
done
```

`--print` 输出的是 bearer token。Runtime 从 Secrets Manager 读取它，并写入容器 `/dev/shm` 中权限为 `0600` 的临时 Drive9 context；token 不会出现在 CLI 参数、CLI 子进程环境或持久卷中。不要执行 `drive9 ctx import`。本测试中 agent-a 和 agent-b 必须写入同一个 token，二者使用 `/agentcore-tests/<TEST_RUN_ID>/shared`；agent-c 使用另一个只读 token，仅授权 `/agentcore-tests/<TEST_RUN_ID>/agent-c`。SecretString 为 `{"token":"<TOKEN>","server":"https://api.drive9.ai"}`：

`/:pseudoroot` 只用于建立 Drive9 虚拟命名空间；数据操作权限仍只授予上面列出的精确前缀。应用层同时强制所有请求路径为相对路径，并把它们拼接到该 Runtime 的 `BASE_REMOTE`。请求 payload 中的 `:/...`、`/...` 或含 `..` 的路径会在任何 Drive9 命令执行前被拒绝。

```bash
aws secretsmanager create-secret --name "drive9/agentcore/${TEST_RUN_ID}-agent-a" --secret-string "$(jq -n --arg t "$(cat agent-a.token)" --arg s "$DRIVE9_SERVER" '{token:$t,server:$s}')"
aws secretsmanager create-secret --name "drive9/agentcore/${TEST_RUN_ID}-agent-b" --secret-string "$(jq -n --arg t "$(cat agent-b.token)" --arg s "$DRIVE9_SERVER" '{token:$t,server:$s}')"
aws secretsmanager create-secret --name "drive9/agentcore/${TEST_RUN_ID}-agent-c" --secret-string "$(jq -n --arg t "$(cat agent-c.token)" --arg s "$DRIVE9_SERVER" '{token:$t,server:$s}')"
```

创建后应检查 Secret 中 token 非空；不要只检查 `create-secret` 的返回码：

```bash
for agent in a b c; do
  secret_id="drive9/agentcore/${TEST_RUN_ID}-agent-${agent}"
  token_length=$(aws secretsmanager get-secret-value --secret-id "$secret_id" --region "$AWS_REGION" --query SecretString --output text | jq -r '.token // .api_key // "" | length')
  test "$token_length" -gt 0 || { echo "empty token in $secret_id" >&2; exit 1; }
done
```

## 3. 构建和推送 ARM64 镜像

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_REPO=drive9-agentcore-test
export IMAGE_TAG=$(date -u +%Y%m%d%H%M%S)
export IMAGE_URI=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO:$IMAGE_TAG
aws ecr describe-repositories --repository-name $ECR_REPO --region $AWS_REGION >/dev/null 2>&1 || aws ecr create-repository --repository-name $ECR_REPO --region $AWS_REGION
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
docker buildx build --platform linux/arm64 --tag $IMAGE_URI --push .
docker buildx imagetools inspect $IMAGE_URI | rg 'linux/arm64'
```

输出必须包含 `linux/arm64`。Dockerfile 使用 ARM64 Drive9 CLI 下载地址；不需要执行 CPU 测试。

## 4. 部署 Capacity Provider 和 Runtime

```bash
export CAPACITY_PROVIDER_OPERATOR_ROLE_ARN=arn:aws:iam::$AWS_ACCOUNT_ID:role/<operator-role>
export EBS_KMS_KEY_ID=arn:aws:kms:$AWS_REGION:$AWS_ACCOUNT_ID:key/<customer-managed-key-id>
export AGENT_RUNTIME_ROLE_ARN_AGENT_A=arn:aws:iam::$AWS_ACCOUNT_ID:role/<agent-a-runtime-role>
export AGENT_RUNTIME_ROLE_ARN_AGENT_B=arn:aws:iam::$AWS_ACCOUNT_ID:role/<agent-b-runtime-role>
export AGENT_RUNTIME_ROLE_ARN_AGENT_C=arn:aws:iam::$AWS_ACCOUNT_ID:role/<agent-c-runtime-role>
export CAPACITY_PROVIDER_VOLUME_NAME_AGENT_A=scratch-agent-a
export CAPACITY_PROVIDER_VOLUME_NAME_AGENT_B=scratch-agent-b
export CAPACITY_PROVIDER_VOLUME_NAME_AGENT_C=scratch-agent-c
export SUBNET_IDS=subnet-private-a,subnet-private-b
export SECURITY_GROUP_IDS=sg-agentcore-runtime
export INSTANCE_TYPE=c6g.large
export CAPACITY_PROVIDER_NAME=drive9_arm64_$RANDOM
export PROVIDER_MAX_LIFETIME=3600
export RUNTIME_MAX_LIFETIME=1800
export RUNTIME_IDLE_TIMEOUT=300
export AGENTCORE_CONTROL_METHOD=auto
export AUTHZ_DISCOVERY_URL=https://<issuer>/.well-known/openid-configuration
export AUTHZ_ALLOWED_CLIENTS=<oauth-client-id>
# 如果 access token 带 aud，再配置：
export AUTHZ_ALLOWED_AUDIENCES=<resource-server-audience>
python3 deploy.py
```

`deploy.py` 默认创建 `LINUX_ARM64` Capacity Provider，并在其中创建三个具名 EBS volume；所有 volume 都强制使用 `EBS_KMS_KEY_ID` 指定的客户管理 KMS key 加密。每个 Runtime 只把自己的 volume 挂载到 `/mnt/scratch`，同时使用自己的 execution role 和 Secret。三个 role ARN、volume name 或 Secret ID 只要有任意重复，部署会在调用 AWS 前失败。默认 Secret 名为 `drive9/agentcore/<TEST_RUN_ID>-agent-a|b|c`；如需覆盖，可设置 `DRIVE9_SECRET_ID_AGENT_A/B/C`。

每个 execution role 的 Secrets Manager 策略必须只允许读取自己的 Secret ARN，并显式避免 `Resource: "*"` 或包含其他 tenant Secret 的通配符。例如 agent-a role 中 Secret 相关语句应为：

```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:us-east-2:<ACCOUNT_ID>:secret:drive9/agentcore/<TEST_RUN_ID>-agent-a-*"
}
```

agent-b、agent-c 分别替换为自己的精确 Secret ARN；不要把三条资源合并到一个共享 role。ECR、日志等 Runtime 基础权限也分别附加到三个 role。部署调用者还需要 `secretsmanager:DescribeSecret` 和 `iam:SimulatePrincipalPolicy`：`deploy.py` 会在创建任何资源前解析三个 Secret ARN，并验证每个 role 只能读取自己的 Secret；跨 tenant 为 Allow、自己的 Secret 非 Allow，或不同 ID 最终解析到同一个 Secret 时都会终止部署。脚本还会为每个 Runtime 配置 `customJWTAuthorizer`、允许的 scope 及 `Authorization` header 转发；应用会再次执行 JWT 与 action-scope 校验。`auto` 优先 boto3 control-plane SDK；若 boto3 缺少 Capacity Provider 方法则自动改用 `aws bedrock-agentcore-control`。

## 5. OAuth 单步调用

获取一个短期 access token，放入环境变量，并生成长度至少 33 个字符的 Session ID。不要把 token 写进 `.env`、`deployment.json`、命令行参数或测试报告：

```bash
export AGENTCORE_BEARER_TOKEN='<short-lived-access-token>'
export SESSION_A=agent-a-primary-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
python3 tests/invoke_action.py --method oauth --deployment deployment.json --agent agent-a --session-id "$SESSION_A" --payload '{"action":"read","path":"."}'
```

`read` token 可执行读取类 action；`preflight` 需要 `drive9.operator`，`mount_test`/`git_*` 需要 `drive9.admin`。缺少 JWT 或 JWT 无效时，AgentCore 边界返回 HTTP 401；JWT 有效但 scope 不足时，应用返回 `status: DENIED`，且目标 handler 不会执行。单独的 IAM invoke grant 不能绕过该模型。`sdk`、`cli` 和 `auto` 仅保留用于旧 IAM-authorized Runtime 的兼容诊断，不适用于本项目新部署的 JWT Runtime。

## 6. 回归测试

完整回归包含 operator/admin action，因此先设置短期 `drive9.admin` token：

先跳过可能受平台限制的 FUSE mount；安全的本地 Git 测试仍会执行：

```bash
python3 tests/run_tests.py --deployment deployment.json --skip-mount
```

测试包括 preflight、CRUD、append、copy/move/list/stat、A/B 同路径目录快照比较、C 对 A/B 共享目录的不可见性、跨 Runtime 持久化、handoff、C Agent 自己目录的只读权限、find/search 以及新 Session 恢复。A/B 快照测试会分别通过两个 Runtime 列出 `functional/`，规范化后比较结果；C 隔离测试会让 agent-c 对 A/B 共享目录执行 `list`，预期得到不可访问结果，Drive9 可能返回 `fs access denied` 或 `not found` 来隐藏无权路径。双方目录内容、C 的拒绝结果和比较结论会打印到回归日志，并写入 `results.jsonl` 和 `report.md`。脚本不包含 CPU probe、CPU benchmark 或并发 CPU workload。结果写入 `artifacts/<TEST_RUN_ID>/results.jsonl`、`report.md` 和 `sessions.json`。出现 `FAIL` 时退出码为 1。

使用 `--skip-mount` 时仅把 FUSE 标记为 `SKIPPED`。Git 测试仍会运行，因为 Git 只在容器本地私有临时目录中以非 root 用户执行，不再依赖 FUSE，也不会读取 Drive9 上的 `.git`、hooks 或 repository config。

如需同时验证 FUSE：

```bash
python3 tests/run_tests.py --deployment deployment.json
```

AgentCore 未提供 `/dev/fuse` 或 mount capability 时，只有 FUSE 标记为 `PLATFORM_BLOCKED`，整体为 `CONDITIONAL GO`，不影响 CLI/API 和安全本地 Git 验收。`git_prepare` 发布普通 JSON 快照到 Drive9，`git_verify` 只验证 JSON schema，不会对远程内容调用 Git。

## 7. 清理

保留报告后，使用 `deployment.json` 中的 ID 删除 Runtime、Capacity Provider session、Capacity Provider，并撤销临时 Drive9 token。只清理 `:/agentcore-tests/<TEST_RUN_ID>/shared` 和 `:/agentcore-tests/<TEST_RUN_ID>/agent-c`，不要删除其他 workspace 数据。删除顺序应为 Runtime -> Capacity Provider；异步删除完成后再删除 ECR 镜像和测试 Secret。

```bash
CP_ID=$(jq -r .capacity_provider_id deployment.json)
for SID in "${SESSION_A:-}" "${SESSION_B:-}" "${SESSION_C:-}" "${SESSION_A_NEW:-}"; do
  [ -n "$SID" ] && aws bedrock-agentcore delete-capacity-provider-session --capacity-provider-id "$CP_ID" --session-id "$SID" --region "$AWS_REGION" || true
done
for AGENT in agent-a agent-b agent-c; do
  RID=$(jq -r ".runtimes[\"$AGENT\"].agent_runtime_id" deployment.json)
  [ "$RID" != "null" ] && aws bedrock-agentcore-control delete-agent-runtime --agent-runtime-id "$RID" --region "$AWS_REGION" || true
done
aws bedrock-agentcore-control delete-capacity-provider --capacity-provider-id "$CP_ID" --region "$AWS_REGION" || true
```

AWS CLI 2.36.x 要求 AgentCore control-plane 删除操作的 `--client-token` 至少为 33 个字符；如果手工补充该参数，请使用 UUID，例如 `cleanup-runtime-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')`。删除 Runtime 后应等待其进入 `DELETED` 或确认不存在，再删除 Capacity Provider。Drive9 scoped token 不能调用 token 管理 API；撤销临时 token 时应切回 owner context，再执行 `drive9 token revoke --api-key-file agent-a.token` 等命令。

## 8. 故障排查

| 现象 | 检查 |
|---|---|
| `create-capacity-provider` 不存在 | 升级 AWS CLI/boto3；或设置 `AGENTCORE_CONTROL_METHOD=cli`。若当前 PyPI 镜像最高只提供 boto3 1.42.x，使用本项目 `requirements.txt` 的兼容下限并让部署脚本走 CLI control plane。|
| Runtime 启动 `SyntaxError` | 重新构建并检查 ECR digest，确认镜像为 `linux/arm64`。旧 Runtime 的 `SyntaxError: '(' was never closed` 不能代表当前代码。|
| Drive9 401/403 | 确认 token 未过期、Secret JSON 正确、scope 覆盖测试目录，并确认 Anonymous/TiDBCloud server 匹配。|
| `Drive9 secret JSON must contain token or api_key` 或 `Drive9 secret token is empty` | Secret 可以被读取但 token 字段缺失或为空。检查 `agent-*.token` 文件大小，重新执行 `drive9 token issue ... --print`，确认 `test -s` 通过后再用 `put-secret-value` 更新 Secret。|
| DNS/HTTPS timeout | 检查私有子网 NAT、DNS 支持、路由和出站 443。|
| Secret `AccessDenied` | 给 Runtime Execution Role 授予对应 Secret 的 `secretsmanager:GetSecretValue`。|
| Runtime 调用 HTTP 401 | 检查 `AGENTCORE_BEARER_TOKEN` 是否过期，以及 issuer、JWKS、client/audience 是否与部署的 authorizer 一致。|
| 响应为 `status: DENIED` | JWT 已通过验证，但 token 没有该 action 所需 scope；按最小权限签发正确 scope，不要扩大 IAM grant。|
| Runtime 读取了旧 token 或找不到 Secret | 确认 `deployment.json` 的三个 `secret_id` 是 `drive9/agentcore/<TEST_RUN_ID>-agent-a|b|c`，不要使用无运行 ID 的旧 Secret 名。|
| FUSE `operation not permitted`、`/dev/fuse` 不存在，或 `/mnt/drive9-*` 创建返回 `Permission denied` | 平台能力限制。当前版本会将这些情况标记为 `PLATFORM_BLOCKED`，保留 CLI/API 结果并按 `CONDITIONAL GO` 记录；只有非权限类挂载错误才标记为 `FAIL`。|
