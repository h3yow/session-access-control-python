# 登录认证与会话访问控制（本地、无外部依赖）

一套纯进程内、可在单测中完全复现的认证 / 会话 / 权限判定能力。
不依赖任何外部服务、数据库或真实凭据：用户密码使用本地加盐 SHA-256
（`authsys/security.py`，仅用于演示），会话与资源全部存放在内存中。

## 模块结构

| 文件 | 职责 |
| --- | --- |
| `authsys/errors.py` | `DenyReason` 枚举与携带确定原因的 `AuthError` |
| `authsys/models.py` | `User / Role / Resource / Session / AccessDecision` 等数据模型 |
| `authsys/security.py` | 本地加盐密码哈希与恒定时间比较 |
| `authsys/store.py` | 线程安全会话存储（单把 `RLock` + 活索引 + 死信表） |
| `authsys/service.py` | 登录、凭据校验、刷新轮换、撤销、受保护写 |
| `authsys/access.py` | 基于角色（RBAC）的资源访问判定 |
| `tests/` | 生命周期、并发刷新、写保护、越权访问等 30 个用例 |

## 会话生命周期

```
login ──► Session(token, proof, version=1,
                  expires_at=now+滑动TTL,
                  absolute_expires_at=now+绝对TTL)
           │
           ├─ authenticate(token)      有效期内可访问受保护资源
           ├─ refresh(old_token)       延长滑动 TTL（不突破绝对 TTL）
           │      └─ 旧 token/proof 立即作废，换发全新 token/proof，version+1
           ├─ logout / revoke_session  显式撤销，凭据立即不可用
           └─ 超过 expires_at / absolute_expires_at  => SESSION_EXPIRED
```

关键性质：

- **刷新即轮换**：刷新成功的同一临界区内，旧 token 进入“死信表”并摘除活索引，
  旧 proof 同步作废。旧凭据立即、永久得到 `session_rotated` 结论。
- **并发刷新唯一胜出**：`refresh` 在存储锁内完成“校验 → 版本检查 → 换发 →
  替换”。32 个并发重复刷新恰好 1 个成功，其余被明确拒绝
  （`session_rotated` 或带乐观版本号时的 `refresh_conflict`），
  任何时刻只有一个有效 token，不会并存多个会话。
- **新旧对象分离**：刷新 / 写操作以“生成新 `Session` 对象并整体替换”推进，
  调用方持有的旧快照不被改写，从根上避免“旧 token 引用被悄悄更新”。
- **滑动 + 绝对双 TTL**：刷新延长滑动过期时间，但不能突破绝对过期时间；
  绝对过期后连刷新也只能得到 `session_expired`。

## 权限模型（RBAC）

- 角色：`admin / owner / user / guest`。
- `owner` 不是用户的全局角色，而是在
  `user.user_id == resource.owner_id` 时**对该资源派生**的角色。
- 每个 `Resource` 显式声明三类策略集合：
  `read_roles / write_roles / delete_roles`；判定为
  “用户有效角色集合 ∩ 该操作允许角色集合”是否非空。
- **管理员边界**：`admin` 对他人资源的能力完全来自策略表（默认可读写删），
  但不会因此被当作所有者（不派生 `owner`）。
- 判定是无状态纯计算，只依赖 用户角色 + 所有者关系 + 资源策略，
  因此结论**与请求顺序、并发无关**，连续 200 轮/24 线程结论一致。
- 越权返回 `AccessDecision(allowed=False, reason=access_denied_role, basis=...)`，
  `basis` 记录命中/缺失角色与所有权，供审计；凭据类问题则抛 `AuthError`。

## 拒绝原因语义（`DenyReason`）

| 原因 | 语义 | 触发场景 |
| --- | --- | --- |
| `invalid_credentials` | 用户名/密码错误 | 登录 |
| `session_not_found` | 凭据从未签发或无活会话 | 认证/刷新 |
| `session_expired` | 超过滑动或绝对有效期 | 认证/刷新（**与下列二者可区分**） |
| `session_rotated` | 凭据已被刷新轮换 | 旧 token 重放 |
| `session_revoked` | 被登出/管理员吊销 | 显式撤销后使用 |
| `refresh_conflict` | 乐观版本不匹配的并发刷新 | 带 `expected_version` 刷新落败 |
| `access_denied_role` | 角色不满足资源策略 | 越权读写删 |
| `resource_not_found` | 资源未注册 | 访问不存在资源 |
| `proof_missing` | 写操作缺少保护凭据 | 受保护写未带 proof |
| `proof_mismatch` | 保护凭据错误 | proof 与会话不符 |
| `proof_expired` | 保护凭据随旧会话轮换/撤销 | 旧 proof 重放 |
| `version_conflict` | 乐观版本号不匹配 | 并发更新，拒绝覆盖 |

写操作保护：所有校验（凭据 → proof → 版本）全部通过后才执行变更回调，
**任一拒绝都不会调用回调、不产生任何状态变更**；成功后版本号 +1，
旧版本号的并发提交一律 `version_conflict`，已生效更新不会丢失或被覆盖。

## 本地验证方法

需要 Python 3.14 与 [uv](https://docs.astral.sh/uv/)。

```bash
# 安装依赖（pytest 为开发依赖）
uv sync

# 运行全部单测
uv run pytest -q

# 查看“请求输入 + 判定依据”日志
uv run pytest -s

# 仅跑并发刷新场景
uv run pytest tests/test_concurrent_refresh.py -q

# 冒烟（FastAPI 入口，仅占位）
uv run uvicorn main:app
```

单测在纯内存夹具（`tests/conftest.py`）中构造
alice（普通用户/`doc-1` 所有者）、bob（普通用户）、root（管理员）、
guest（访客）以及默认资源与受限资源，可离线、确定性地重复执行。
每个用例通过 `print` 输出请求输入，日志处理器实时输出判定依据。
