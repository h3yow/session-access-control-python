"""会话生命周期管理：本地账号登录（含失败限流）、校验、刷新轮换、
撤销、账号状态联动失效、绝对总时长上限、受保护写操作。

并发模型：账号与会话的全部状态读取/变更都在同一把锁内完成，因此
登录计数/锁定、账号状态切换、刷新轮换与受保护写在并发下结论确定。

凭据校验优先级（会话级 > 账号级 > 凭据级 > 时间级）：
已撤销 > 账号状态已变化 > 已轮换 > 超过绝对总时长 > 滑动过期。
"""
from __future__ import annotations

import secrets
import threading
import time
import uuid
from typing import Callable, Optional

from app.accounts import AccountStore, verify_password
from app.models import Decision, DenialReason, Role, Session

# 本地演示账号：仅存于内存，非真实生产凭据。
DEFAULT_ACCOUNTS = [
    ("root", "root-pw", Role.ADMIN, True),
    ("alice", "alice-pw", Role.OWNER, True),
    ("bob", "bob-pw", Role.OWNER, True),
    ("carol", "carol-pw", Role.VIEWER, True),
    ("dave", "dave-pw", Role.VIEWER, False),
]


class AuthService:
    """内存账号 + 会话服务。"""

    def __init__(
        self,
        accounts: Optional[AccountStore] = None,
        ttl_seconds: float = 300.0,
        max_session_seconds: float = 3600.0,
        max_login_failures: int = 5,
        lockout_seconds: float = 300.0,
        clock: Callable[[], float] = None,
    ):
        self._accounts = accounts or AccountStore.with_passwords(DEFAULT_ACCOUNTS)
        self._ttl = ttl_seconds
        self._max_session = max_session_seconds
        self._max_failures = max_login_failures
        self._lockout = lockout_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        # 所有签发过的凭据 -> 会话，用于区分"从未存在"与"已轮换"。
        self._token_index: dict[str, str] = {}
        self._rotated_tokens: set[str] = set()
        # 登录失败计数与锁定截止时间（单调时钟时间戳）。
        self._failures: dict[str, int] = {}
        self._lock_until: dict[str, float] = {}

    # ---- 内部：须在持锁状态下调用 ----

    def _check_locked(self, token: str) -> tuple[Decision, Optional[Session]]:
        session_id = self._token_index.get(token)
        if session_id is None:
            return Decision.deny(DenialReason.SESSION_NOT_FOUND, "凭据从未签发"), None
        session = self._sessions[session_id]
        now = self._clock()
        # 1. 会话级撤销优先。
        if session.revoked:
            return Decision.deny(DenialReason.SESSION_REVOKED, "会话已撤销"), None
        # 2. 账号状态：停用/改口令会让 epoch 递增，旧会话立即失效。
        account = self._accounts.get(session.user_id)
        if account is None or account.epoch != session.epoch:
            return (
                Decision.deny(
                    DenialReason.ACCOUNT_STATE_CHANGED,
                    f"账号 {session.user_id} 状态已变化（停用或口令已修改），"
                    f"签发时代次 {session.epoch}，当前代次 "
                    f"{account.epoch if account else '账号已删除'}",
                ),
                None,
            )
        # 3. 凭据级：已被一次刷新轮换取代。
        if token in self._rotated_tokens:
            return Decision.deny(DenialReason.TOKEN_ROTATED, "凭据已被轮换"), None
        # 4. 绝对总时长上限：无论怎么刷新都不能突破登录时刻起算的上限。
        if now >= session.absolute_expires_at:
            return (
                Decision.deny(
                    DenialReason.SESSION_LIFETIME_EXCEEDED,
                    f"会话总时长已达上限 {self._max_session:g}s（登录时刻起算）",
                ),
                None,
            )
        # 5. 滑动过期。
        if now >= session.expires_at:
            return Decision.deny(DenialReason.SESSION_EXPIRED, "会话已过期"), None
        return Decision.allow("凭据有效"), session

    # ---- 本地账号登录 ----

    def login(self, user_id: str, password: str) -> tuple[Decision, Optional[Session]]:
        """基于本地账号校验口令并签发会话。

        失败原因可区分：账号不存在 / 口令错误 / 账号停用 / 已被锁定。
        连续失败达到上限后进入锁定窗口，窗口内即使口令正确也以
        ACCOUNT_LOCKED 拒绝（与 BAD_PASSWORD 区分）。计数与锁定在
        同一把锁内更新，并发失败不会少算。
        """
        with self._lock:
            now = self._clock()
            account = self._accounts.get(user_id)
            if account is None:
                return (
                    Decision.deny(
                        DenialReason.ACCOUNT_NOT_FOUND, f"账号 {user_id} 不存在"
                    ),
                    None,
                )
            # 锁定判定优先于一切；锁定窗口过期后清空计数重新开始。
            until = self._lock_until.get(user_id, 0.0)
            if until > now:
                return (
                    Decision.deny(
                        DenialReason.ACCOUNT_LOCKED,
                        f"账号 {user_id} 已锁定，剩余 {until - now:g}s；"
                        f"连续失败达到 {self._max_failures} 次",
                    ),
                    None,
                )
            if until:
                self._lock_until.pop(user_id, None)
                self._failures.pop(user_id, None)
            if not account.enabled:
                return (
                    Decision.deny(
                        DenialReason.ACCOUNT_DISABLED, f"账号 {user_id} 已被停用"
                    ),
                    None,
                )
            if not verify_password(password, account.password_hash):
                failures = self._failures.get(user_id, 0) + 1
                self._failures[user_id] = failures
                if failures >= self._max_failures:
                    self._lock_until[user_id] = now + self._lockout
                    self._failures.pop(user_id, None)
                    return (
                        Decision.deny(
                            DenialReason.BAD_PASSWORD,
                            f"口令错误（连续第 {failures} 次），账号已进入 "
                            f"{self._lockout:g}s 锁定",
                        ),
                        None,
                    )
                return (
                    Decision.deny(
                        DenialReason.BAD_PASSWORD,
                        f"口令错误（连续第 {failures}/{self._max_failures} 次）",
                    ),
                    None,
                )
            # 成功：清空失败计数，按账号当前角色与状态代次签发会话。
            self._failures.pop(user_id, None)
            self._lock_until.pop(user_id, None)
            session = Session(
                session_id=uuid.uuid4().hex,
                user_id=user_id,
                role=account.role,
                token=secrets.token_hex(16),
                csrf_token=secrets.token_hex(16),
                expires_at=now + self._ttl,
                absolute_expires_at=now + self._max_session,
                epoch=account.epoch,
            )
            self._sessions[session.session_id] = session
            self._token_index[session.token] = session.session_id
            return Decision.allow(f"账号 {user_id} 认证通过"), session

    # ---- 校验 / 轮换 / 撤销 ----

    def validate(self, token: str) -> Decision:
        """校验凭据；各类失败必须可区分。"""
        with self._lock:
            decision, _ = self._check_locked(token)
            return decision

    def refresh(self, old_token: str) -> tuple[Decision, Optional[Session]]:
        """轮换凭据并延长滑动有效期，但绝对总时长上限不可突破。

        旧凭据立即失效；并发重复刷新由同一把锁串行化：恰好一个成功，
        其余以 TOKEN_ROTATED 拒绝；若已到绝对上限则一律以
        SESSION_LIFETIME_EXCEEDED 拒绝（与普通过期/撤销/轮换区分）。
        """
        with self._lock:
            decision, session = self._check_locked(old_token)
            if not decision.allowed:
                return decision, None
            now = self._clock()
            self._rotated_tokens.add(old_token)
            # 新的滑动过期点不得超过绝对上限；剩余不足一个 TTL 时截到上限。
            new_expiry = min(now + self._ttl, session.absolute_expires_at)
            session.token = secrets.token_hex(16)
            session.csrf_token = secrets.token_hex(16)
            session.expires_at = new_expiry
            session.version += 1
            self._token_index[session.token] = session.session_id
            return Decision.allow("凭据已轮换（绝对总时长上限不变）"), session

    def get_active_session(self, token: str) -> Optional[Session]:
        """在确认凭据有效后取回会话对象；无效时返回 None。"""
        with self._lock:
            decision, session = self._check_locked(token)
            return session if decision.allowed else None

    def revoke(self, session_id: str) -> Decision:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return Decision.deny(DenialReason.SESSION_NOT_FOUND, "会话不存在")
            session.revoked = True
            return Decision.allow("会话已撤销")

    # ---- 账号状态管理：停用 / 启用 / 改口令，联动既有会话 ----

    def disable_account(self, user_id: str) -> Decision:
        """停用账号：epoch 递增，该账号所有既有会话立即失效。"""
        with self._lock:
            account = self._accounts.get(user_id)
            if account is None:
                return Decision.deny(
                    DenialReason.ACCOUNT_NOT_FOUND, f"账号 {user_id} 不存在"
                )
            self._accounts.set_enabled(user_id, False)
            return Decision.allow(
                f"账号 {user_id} 已停用，状态代次 -> {account.epoch}，既有会话全部失效"
            )

    def enable_account(self, user_id: str) -> Decision:
        """重新启用账号（不回退 epoch，旧会话仍失效，需重新登录）。"""
        with self._lock:
            account = self._accounts.get(user_id)
            if account is None:
                return Decision.deny(
                    DenialReason.ACCOUNT_NOT_FOUND, f"账号 {user_id} 不存在"
                )
            self._accounts.set_enabled(user_id, True)
            return Decision.allow(f"账号 {user_id} 已启用，需重新登录")

    def change_account_password(self, user_id: str, new_password: str) -> Decision:
        """修改口令：epoch 递增，该账号所有既有会话立即失效。"""
        with self._lock:
            account = self._accounts.get(user_id)
            if account is None:
                return Decision.deny(
                    DenialReason.ACCOUNT_NOT_FOUND, f"账号 {user_id} 不存在"
                )
            self._accounts.change_password(user_id, new_password)
            return Decision.allow(
                f"账号 {user_id} 口令已修改，状态代次 -> {account.epoch}，"
                "既有会话全部失效"
            )

    def update_session(
        self,
        token: str,
        csrf_token: Optional[str],
        expected_version: Optional[int],
        mutate: Callable[[Session], None],
    ) -> Decision:
        """受保护写操作：校验凭据 + CSRF + 乐观版本。

        任何校验失败都不执行 mutate，且在锁内完成读取-校验-写入，
        同一会话的并发更新不会丢失或被覆盖。
        """
        with self._lock:
            decision, session = self._check_locked(token)
            if not decision.allowed:
                return decision
            if csrf_token is None:
                return Decision.deny(DenialReason.CSRF_MISSING, "缺少保护信息")
            if csrf_token != session.csrf_token:
                return Decision.deny(DenialReason.CSRF_MISMATCH, "保护信息不匹配")
            if expected_version is not None and expected_version != session.version:
                return Decision.deny(
                    DenialReason.VERSION_CONFLICT,
                    f"版本冲突: 期望 {expected_version}, 实际 {session.version}",
                )
            mutate(session)
            session.version += 1
            return Decision.allow(f"已更新到版本 {session.version}")
