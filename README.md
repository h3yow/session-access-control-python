# 登录认证与会话访问控制（Python / FastAPI）

纯内存、不依赖任何外部服务或真实凭据的本地账号登录、失败限流、会话凭据轮换、
账号状态联动失效、续期总时长上限与基于角色的资源访问控制实现。
所有判定都返回结构化结论 `Decision(allowed, reason, detail)`，不同的失败场景在
`reason` 上**可区分**，账号与会话的全部状态读取/变更都在同一把锁内串行化，
保证并发下结论确定。

## 目录结构

```
app/models.py    # Role / TokenStatus / DenialReason / Account 无关类型 / Session / Resource / Decision
app/accounts.py  # Account / AccountStore：本地账号、pbkdf2 口令校验、状态代次 epoch
app/auth.py      # AuthService：本地登录+限流、校验、刷新轮换、撤销、
                 #             账号状态联动、绝对时长上限、受保护写操作
app/access.py    # can_read / can_write：基于角色的资源访问判定（纯函数）
main.py          # FastAPI 路由层（HTTP 演示）
tests/           # 登录限流、状态联动、续期上限、生命周期、访问矩阵、并发、HTTP 测试
```

## 本地账号模型

- 账号仅存于内存（`AccountStore`），字段：`user_id`、口令派生串 `password_hash`、
  `role`、`enabled`、状态代次 `epoch`。演示账号（**全部为虚构口令，非真实凭据**）：

  | 账号 | 口令 | 角色 | 状态 |
  |---|---|---|---|
  | `root` | `root-pw` | admin | 启用 |
  | `alice` | `alice-pw` | owner | 启用 |
  | `bob` | `bob-pw` | owner | 启用 |
  | `carol` | `carol-pw` | viewer | 启用 |
  | `dave` | `dave-pw` | viewer | **停用** |

- 口令使用标准库 `hashlib.pbkdf2_hmac`（sha256，200000 轮，随机盐）派生存储，
  校验用 `hmac.compare_digest` 常量时间比较；不引入任何新的第三方依赖。
- **登录时角色以账号记录为准**，请求体只有 `user_id/password`，请求方无法自行指定角色。

## 登录与限流判定语义

`POST /login`（`AuthService.login(user_id, password)`）按以下顺序判定，
四类失败互相**可区分**，且任何失败都不会建立会话：

1. 账号不存在 → `account_not_found`；
2. 账号处于锁定窗口（见下）→ `account_locked`——**即使口令正确也被挡**，
   与"口令不对"是不同结论；
3. 账号被停用 → `account_disabled`；
4. 口令不匹配 → `bad_password`，同时该账号连续失败计数 +1。

**限流**：默认同一账号连续失败 `5` 次（`max_login_failures`）后进入
`300s` 锁定窗口（`lockout_seconds`，测试中为 60s）。触发锁定的第 5 次请求
仍返回 `bad_password`，其后的一切登录尝试（含正确口令）返回 `account_locked`；
窗口结束后计数清零、可正常登录；登录成功也会清零计数。计数、锁定时间戳与
会话签发在同一把锁内更新，并发失败不会少算（见
`test_concurrent_bad_logins_are_counted_exactly`：16 个同时失败恰好
5 个 `bad_password`、11 个 `account_locked`）。

## 账号状态变化联动会话失效

每个账号维护单调递增的**状态代次 `epoch`**，会话签发时快照账号当前代次：

- 管理员停用账号 `POST /admin/accounts/{id}/disable`（`disable_account`）或
  本人修改口令 `POST /account/password`（`change_account_password`）都会让
  账号 `epoch += 1`；
- 此后该账号**此前签发的所有会话**在访问与续期时一律得到
  `account_state_changed`，凭据不再可用；同一批旧凭据结论完全一致，
  不会出现一部分请求成功、一部分失败；
- 重新启用账号（`enable_account`）**不会回退 epoch、不复活旧会话**，需重新登录；
- 该结论与会话撤销 `session_revoked`、自然过期 `session_expired` 明确区分；
- 状态切换与并发请求由同一把锁串行：停用/改口令完成之后不可能有请求漏网成功
  （`test_concurrent_validate_around_disable_no_success_after`、
  `test_concurrent_requests_around_password_change_no_success_after`）。

## 会话生命周期与续期总时长上限

1. **登录**：签发会话，含 `token`、`csrf_token`、滑动过期时间 `expires_at`、
   **绝对过期时间 `absolute_expires_at = 登录时刻 + max_session_seconds`**（默认 3600s，测试 200s）、
   账号代次 `epoch` 与乐观版本 `version`（初始 0）。
2. **访问**：携带 `X-Auth-Token`。服务端校验顺序：
   **已撤销 → 账号状态已变化 → 已轮换 → 超过总时长上限 → 滑动过期 → 有效**
   （会话级 > 账号级 > 凭据级 > 时间级）。
3. **刷新/轮换** `POST /refresh`：旧凭据立即进入轮换集合而失效（`token_rotated`），
   新 `token/csrf_token` 签发、`version` 加一、滑动过期点重算为
   `min(now + TTL, absolute_expires_at)`——**无论刷新多少次都不能突破登录时刻
   起算的总时长上限**。到达上限后访问与续期得到 `session_lifetime_exceeded`，
   与普通过期 `session_expired`、撤销 `session_revoked`、凭据被替换
   `token_rotated` 都可区分。上限附近的并发续期由锁串行：恰好一个成功，
   其余确定为 `token_rotated`；若所有请求都发生在上限点或之后，则全部为
   `session_lifetime_exceeded`，不会并存多个有效会话
   （`test_concurrent_refresh_near_cap_only_one_succeeds`、
   `test_concurrent_refresh_at_cap_all_rejected_consistently`）。
4. **撤销** `POST /revoke/{session_id}`：会话级失效，返回 `session_revoked`。
5. **滑动过期**：`clock() >= expires_at` 且未到绝对上限时返回 `session_expired`；
   测试用可手动推进的 `FakeClock` 构造确定性时间场景。

## 权限模型

| 角色 | 读 public | 读他人 private | 读自有 | 写任意 | 写自有 |
|---|---|---|---|---|---|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `owner` | ✅ | ❌ `not_owner` | ✅ | ✅（管理员能力） | ✅ |
| `viewer` | — | ❌ `forbidden_role` | — | ❌ `forbidden_role` | ❌ |

判定是无状态纯函数，结果只取决于 `(用户, 角色, 资源)`，与请求顺序、并发无关。
有权限的合法写入会真正修改资源内容，随后读取能看到新内容
（`test_http_authorized_write_takes_effect_and_reads_back`）。

## 受保护写操作与会话并发更新

`AuthService.update_session(token, csrf_token, expected_version, mutate)` 在锁内完成
"读取-校验-写入"：凭据校验 → CSRF（缺失 `csrf_missing` / 不匹配 `csrf_mismatch`）
→ 乐观版本（不一致 `version_conflict`）→ 执行 `mutate` 且 `version += 1`。
任何拒绝都不执行 `mutate`；32 个并发更新全部串行生效、计数与版本不丢失；
同版本两个写请求一成一败。正向写入后读回内容已更新（
`test_protected_write_positive_takes_effect_and_reads_back`）。

## 拒绝原因语义（`DenialReason`）

| reason | 语义 | HTTP |
|---|---|---|
| `account_not_found` | 登录账号不存在 | 401 |
| `bad_password` | 账号存在但口令不对（连续计数 +1） | 401 |
| `account_disabled` | 账号已被停用 | 401 |
| `account_locked` | 连续失败超限，处于锁定窗口（口令正确也拒绝） | 401 |
| `account_state_changed` | 账号被停用或口令被修改，签发时的状态代次已过期 | 401 |
| `session_not_found` | 凭据从未签发（或未携带凭据） | 401 |
| `session_expired` | 超过滑动有效期（未到总时长上限） | 401 |
| `session_lifetime_exceeded` | 达到登录时刻起算的总时长上限 | 401 |
| `token_rotated` | 凭据曾有效，但已被一次刷新轮换取代 | 401 |
| `session_revoked` | 凭据所在会话已被撤销 | 401 |
| `forbidden_role` | 角色能力不足 | 403 |
| `not_owner` | 非管理员且不是目标资源所有者 | 403 |
| `csrf_missing` / `csrf_mismatch` | 写操作缺少/错误保护信息 | 403 |
| `version_conflict` | 乐观版本不匹配，写入已被先行提交 | 409 |

错误响应统一为：
`{"detail": {"allowed": false, "reason": "<枚举值>", "detail": "判定依据"}}`

## 兼容范围

- 登录接口由"请求方自带角色"改为"本地账号 + 口令、角色取账号"，这是有意的
  安全收紧：旧的 `{"user_id","role"}` 请求体不再被接受；
- 会话结构新增 `absolute_expires_at`、`epoch` 字段；旧的刷新/撤销/权限/CSRF/
  乐观版本语义与拒绝原因全部保留，原有用例（轮换、旧凭据重放、越权拒绝、
  写保护与版本冲突）均无回归；
- 新增管理接口 `POST /admin/accounts/{id}/disable|enable`（需 admin 会话）与
  `POST /account/password`（需本人会话 + CSRF）；
- 所有数据仍仅在内存中，进程重启即清空，不接任何外部服务。

## 本地验证

```bash
uv sync
uv run pytest                 # 运行全部 49 个用例（含限流/联动/上限并发场景与 INFO 判定日志）
uv run pytest -q -s           # 静默模式但打印日志
uv run fastapi dev main.py    # 启动 HTTP 演示
```

典型手工验证（口令均为虚构演示值）：

```bash
# 本地账号登录（角色由账号决定）
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"user_id":"alice","password":"alice-pw"}'
# 连续 5 次错误口令 -> 第 6 次即使口令正确也得到 account_locked
for i in $(seq 5); do curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"user_id":"bob","password":"wrong"}'; done
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"user_id":"bob","password":"bob-pw"}'
# 管理员停用账号后，该账号旧会话立即得到 account_state_changed
curl -s -X POST localhost:8000/admin/accounts/bob/disable -H "x-auth-token: <admin-token>"
# 旧 token 重放 -> 401 token_rotated；达到总时长上限 -> 401 session_lifetime_exceeded
curl -s localhost:8000/resource/r-alice -H "x-auth-token: <旧token>"
```

测试日志中每条请求都会打印**输入**（账号/操作编号/时间点）与**判定依据**
（`allowed/reason/detail`），便于核对限流计数、状态联动收口与上限附近
并发续期结论的一致性。
