# 登录认证与会话访问控制（Python / FastAPI）

纯内存、不依赖任何外部服务或真实凭据的本地账号登录、会话管理、凭据轮换与基于角色的资源访问控制实现。
所有判定都返回结构化结论 `Decision(allowed, reason, detail)`，不同的失败场景在 `reason` 上**可区分**，
并在全部状态变更路径上使用锁串行化，保证并发下结论确定。

## 目录结构

```
app/models.py    # Role / DenialReason / Session / Account / Resource / Decision
app/accounts.py  # AccountStore：本地账号、口令校验、失败限流锁定、停用/改密
app/auth.py      # AuthService：登录、校验、刷新轮换、撤销、失效联动、受保护写操作
app/access.py    # can_read / can_write：基于角色的资源访问判定（纯函数）
main.py          # FastAPI 路由层（HTTP 演示，含演示用本地账号）
tests/           # 生命周期、账号登录、失效联动、续期上限、访问矩阵、并发、HTTP 端到端
```

## 本地账号模型

账号信息维护在 `AccountStore`（内存）中，每个账号包含：

- `username` / 口令的 **PBKDF2 加盐散列**（不保存明文，比较用恒定时间比较）；
- `role`：会话角色**以账号为准**，登录请求不能自选角色；
- `enabled`：停用标志；
- `epoch`：凭据纪元，停用/启用状态切换与修改口令时递增，用于联动会话失效。

演示账号（`main.py`，全部为假口令，仅用于本地验证）：
`alice`/`bob`（owner）、`carol`（viewer）、`root`（admin）、`dave`（预置停用）。

## 登录与限流判定语义

`AuthService.login(username, password)` 委托 `AccountStore.authenticate`，按以下顺序判定
（全部在账号仓库的同一把锁内完成）：

1. 账号不存在 → `account_unknown`（**不计入**失败次数）；
2. 正处于锁定期 → `account_locked`（**即使口令正确也拒绝**，且不再计数、不延长锁定）；
3. 账号被停用 → `account_disabled`；
4. 口令不匹配 → `password_mismatch`，连续失败计数 +1；达到上限（演示配置 3 次）即进入
   锁定期（演示配置 30s）并清零计数；
5. 通过 → 签发会话，失败计数与锁定状态清零。

三种失败（不存在 / 口令不对 / 已停用）与"正处于锁定中"在 `reason` 上互相可区分，
且失败登录不会建立任何会话。并发登录失败时计数与锁定判定都在锁内串行，
不少算次数、不因并发多放行（见 `test_accounts.py` 的并发用例）。

## 账号状态变化对既有会话的影响

会话签发时记录账号当时的 `epoch`。账号被**停用**或**修改口令**后 `epoch` 递增，
该账号此前签发的所有会话在下一次访问或续期时立即以 `session_invalidated` 失效——
与普通的会话撤销（`session_revoked`）、自然过期（`session_expired`）可区分。

- 失效对**访问和续期同样生效**，不会出现同一批旧凭据有的能用、有的不能用；
- 会话级状态优先于凭据级状态：停用后即使凭据已轮换/已过期，也报 `session_invalidated`；
- 状态切换与并发请求同时发生时，所有判定都在锁内完成：切换完成后不允许再有请求漏网成功
  （见 `test_invalidation.py::test_concurrent_disable_no_request_slips_through`）。

## 会话生命周期与续期总时长上限

1. **登录** `POST /login`：签发会话，含 `token`、`csrf_token`、`expires_at`、
   乐观版本 `version`，并记录登录时刻 `created_at`。
2. **访问**：携带 `X-Auth-Token`。校验顺序：
   **已撤销 → 账号失效 → 已轮换 → 已过期 → 有效**（会话级状态优先于凭据级状态）。
3. **刷新/轮换** `POST /refresh`：旧凭据立即进入轮换集合失效，签发新 `token`/`csrf_token`，
   `version` 加一。并发重复刷新**恰好一个成功**，其余全部以 `token_rotated` 拒绝。
4. **续期总时长上限**：无论刷新多少次，都不能突破从登录时刻算起的 `max_lifetime`：
   - 上限之前刷新，新凭据有效期被截断到上限（`min(now+ttl, created_at+max_lifetime)`）；
   - 到达上限后再续期，以 `session_max_age_exceeded` 明确拒绝——在续期路径上该判定
     **优先于自然过期**，与普通到期、被撤销、凭据已轮换均可区分；
   - 上限附近的并发续期由锁串行化：恰好一个成功，其余得到一致的 `token_rotated`，
     不会同时留下多个有效会话。
5. **撤销** `POST /revoke/{session_id}`：会话级失效，所有凭据返回 `session_revoked`。
6. **过期**：`clock() >= expires_at` 即失效，返回 `session_expired`。

## 权限模型

| 角色 | 读 public | 读他人 private | 读自有 | 写任意 | 写自有 |
|---|---|---|---|---|---|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `owner` | ✅ | ❌ `not_owner` | ✅ | ✅（管理员能力） | ✅ |
| `viewer` | ✅ | ❌ `forbidden_role` | — | ❌ `forbidden_role` | ❌ |

判定是无状态纯函数，结果只取决于 `(用户, 角色, 资源)`，与请求顺序、并发无关。
每次拒绝都在 `detail` 中保留判定依据（谁、对哪个资源、因何被拒）。

## 受保护写操作与会话并发更新

`AuthService.update_session(token, csrf_token, expected_version, mutate)` 在锁内完成
"读取-校验-写入"三步：凭据校验 → 保护信息校验（`csrf_missing` / `csrf_mismatch`）→
乐观版本（`version_conflict`）→ 全部通过才执行 `mutate` 并将 `version` 加一。

**任何拒绝都不会执行 `mutate`**；合法写入真正生效、后续读取可见
（见 `test_concurrency.py::test_protected_write_success_and_visible_afterwards`
与 `test_api.py::test_http_authorized_write_takes_effect_and_is_readable`）。
同一凭据的并发更新在锁内串行，不丢失、不覆盖。

## 拒绝原因语义（`DenialReason`）

| reason | 语义 | HTTP |
|---|---|---|
| `account_unknown` | 登录账号不存在 | 401 |
| `password_mismatch` | 口令不匹配（含触发锁定的最后一次） | 401 |
| `account_disabled` | 账号已停用 | 401 |
| `account_locked` | 连续失败超限，正处于锁定期（口令正确也拒绝） | 401 |
| `session_not_found` | 凭据从未签发（或请求未携带凭据） | 401 |
| `session_expired` | 凭据所在会话已超过有效期 | 401 |
| `token_rotated` | 凭据曾有效，但已被一次刷新轮换取代 | 401 |
| `session_revoked` | 凭据所在会话已被撤销 | 401 |
| `session_invalidated` | 账号停用/改密导致会话被强制失效 | 401 |
| `session_max_age_exceeded` | 续期总时长已达上限，禁止续期 | 401 |
| `forbidden_role` | 角色能力不足（如 viewer 访问 private / 执行写） | 403 |
| `not_owner` | 非管理员且不是目标资源的所有者 | 403 |
| `csrf_missing` | 写操作缺少保护信息 | 403 |
| `csrf_mismatch` | 保护信息与会话当前值不匹配（含轮换后使用旧 csrf） | 403 |
| `version_conflict` | 乐观版本不匹配，写入已被他人先行提交 | 409 |

错误响应统一为：
`{"detail": {"allowed": false, "reason": "<上表枚举值>", "detail": "判定依据"}}`

## 兼容范围

- 仅使用 Python 标准库与仓库既有依赖（FastAPI / pytest），不引入新依赖、不接外部服务；
- 账号、会话、资源全部保存在进程内存中，重启即清空，适合本地演示与测试；
- 登录接口由"自选角色"改为"账号口令校验"，`AuthService.login` 签名相应变化，
  其余会话/权限/保护写语义保持向后兼容；
- 口令散列参数（PBKDF2 迭代次数）、限流阈值、锁定时长、TTL、续期上限均为构造参数，
  测试中用 `FakeClock` 确定性构造过期/锁定/上限场景。

## 本地验证

```bash
uv sync
uv run pytest                 # 运行全部用例（含并发场景与 INFO 判定日志）
uv run pytest -q -s           # 静默模式但打印日志
uv run fastapi dev main.py    # 启动 HTTP 演示
```

典型手工验证：

```bash
# 账号登录（角色由账号决定）
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pw"}'
# 连续 3 次错误口令后，正确口令也会被锁定 30s -> 401 account_locked
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"wrong"}'
# 停用账号后，既有会话访问/续期 -> 401 session_invalidated
curl -s -X POST localhost:8000/accounts/alice/disable
# 修改口令同样使既有会话失效
curl -s -X POST localhost:8000/accounts/alice/password \
  -H 'content-type: application/json' -d '{"new_password":"new-pw"}'
# 刷新（携带登录返回的 token）；旧 token 重放 -> 401 token_rotated
curl -s -X POST localhost:8000/refresh -H "x-auth-token: <token>"
```

测试日志中每个用例都会打印**请求输入**（用户、角色、资源、操作编号、时间推进）与
**判定依据**（`allowed/reason/detail`），便于核对并发下结论的一致性与可区分性。
