# 登录认证与会话访问控制（Python / FastAPI）

纯内存、不依赖任何外部服务或真实凭据的登录认证、凭据轮换与基于角色的资源访问控制实现。
所有判定都返回结构化结论 `Decision(allowed, reason, detail)`，不同的失败场景在 `reason` 上**可区分**，
并在全部状态变更路径上使用单锁串行化，保证并发下结论确定。

## 目录结构

```
app/models.py   # Role / TokenStatus / DenialReason / Session / Resource / Decision
app/auth.py     # AuthService：登录、校验、刷新轮换、撤销、受保护写操作
app/access.py   # can_read / can_write：基于角色的资源访问判定（纯函数）
main.py         # FastAPI 路由层（HTTP 演示）
tests/          # 生命周期、访问矩阵、并发刷新/更新、HTTP 端到端测试
```

## 会话生命周期

1. **登录** `POST /login`（`AuthService.login`）：签发会话，包含访问凭据 `token`、
   保护信息 `csrf_token`、过期时间 `expires_at` 和乐观版本 `version`（初始 0）。
2. **访问**：携带 `X-Auth-Token`。服务端校验顺序为：
   **已撤销 → 已轮换 → 已过期 → 有效**（会话级状态优先于凭据级状态）。
3. **刷新/轮换** `POST /refresh`：成功后旧凭据**立即**进入轮换集合而失效，
   新 `token` 与 `csrf_token` 被签发、TTL 重新计算、`version` 加一。
   - 旧凭据此后任何使用都得到 `token_rotated`（重放攻击可识别）；
   - 并发重复刷新由同一把锁串行化：**恰好一个成功**，其余全部以 `token_rotated` 明确拒绝，
     不会并存多个有效会话。
4. **撤销** `POST /revoke/{session_id}`：会话级失效，该会话所有凭据返回 `session_revoked`。
5. **过期**：`clock() >= expires_at` 即失效，返回 `session_expired`。
   测试中使用可手动推进的 `FakeClock` 构造确定性过期。

## 权限模型

| 角色 | 读 public | 读他人 private | 读自有 | 写任意 | 写自有 |
|---|---|---|---|---|---|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `owner` | ✅ | ❌ `not_owner` | ✅ | ✅（管理员能力） | ✅ |
| `viewer` | ✅ | ❌ `forbidden_role` | — | ❌ `forbidden_role` | ❌ |

判定是无状态纯函数，结果只取决于 `(用户, 角色, 资源)`，与请求顺序、并发无关。
管理员可读写任意资源；普通 `owner` 的边界是"自有资源"；`viewer` 只读 public。
每次拒绝都在 `detail` 中保留判定依据（谁、对哪个资源、因何被拒）。

## 受保护写操作与会话并发更新

`AuthService.update_session(token, csrf_token, expected_version, mutate)` 在锁内完成
"读取-校验-写入"三步：

1. 凭据校验（通过后才有后续）；
2. 保护信息校验：`None` → `csrf_missing`，不匹配 → `csrf_mismatch`；
3. 乐观并发：传入的 `expected_version` 与当前 `version` 不一致 → `version_conflict`；
4. 全部通过才执行 `mutate` 并将 `version` 加一。

**任何拒绝都不会执行 `mutate`，不产生状态变更**；同一凭据的并发更新在锁内串行，
不丢失、不覆盖（见 `test_concurrent_updates_no_lost_writes`：32 个并发更新后计数与版本均为 32）。
乐观版本冲突场景见 `test_optimistic_version_conflict_under_concurrency`：同版本的两个写请求一成一败。

## 拒绝原因语义（`DenialReason`）

| reason | 语义 | HTTP |
|---|---|---|
| `session_not_found` | 凭据从未签发（或请求未携带凭据） | 401 |
| `session_expired` | 凭据所在会话已超过有效期 | 401 |
| `token_rotated` | 凭据曾有效，但已被一次刷新轮换取代 | 401 |
| `session_revoked` | 凭据所在会话已被撤销 | 401 |
| `forbidden_role` | 角色能力不足（如 viewer 访问 private / 执行写） | 403 |
| `not_owner` | 非管理员且不是目标资源的所有者 | 403 |
| `csrf_missing` | 写操作缺少保护信息 | 403 |
| `csrf_mismatch` | 保护信息与会话当前值不匹配（含轮换后使用旧 csrf） | 403 |
| `version_conflict` | 乐观版本不匹配，写入已被他人先行提交 | 409 |

错误响应统一为：
`{"detail": {"allowed": false, "reason": "<上表枚举值>", "detail": "判定依据"}}`

## 本地验证

```bash
uv sync
uv run pytest                 # 运行全部 20 个用例（含并发场景与 INFO 判定日志）
uv run pytest -q -s           # 静默模式但打印日志
uv run fastapi dev main.py    # 启动 HTTP 演示
```

典型手工验证：

```bash
# 登录
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"user_id":"alice","role":"owner"}'
# 刷新（携带返回的 token）
curl -s -X POST localhost:8000/refresh -H "x-auth-token: <token>"
# 用旧 token 重放 -> 401 token_rotated
curl -s localhost:8000/resource/r-alice -H "x-auth-token: <旧token>"
```

测试日志中每个用例都会打印**请求输入**（用户、角色、资源、操作编号）与
**判定依据**（`allowed/reason/detail`），便于核对并发下结论的一致性与可区分性。
