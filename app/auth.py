"""会话生命周期管理：账号登录、校验、刷新轮换、撤销、受保护写操作。

与账号体系的联动：
- 登录必须经 AccountStore 校验口令，会话角色取自账号本身；
- 会话签发时记录账号 epoch，账号停用/改密后 epoch 变化，
  该账号此前签发的所有会话立即以 session_invalidated 失效（访问与续期同样拦截）；
- 续期不能突破从登录时刻算起的总时长上限 max_lifetime，
  到达上限后续期以 session_max_age_exceeded 明确拒绝。
"""
from __future__ import annotations

import secrets
import threading
import time
import uuid
from typing import Callable, Optional

from app.accounts import AccountStore
from app.models import Decision, DenialReason, Session


class AuthService:
    """内存会话服务。

    并发模型：所有状态读取与变更都在同一把锁内完成，
    因此刷新轮换、撤销、账号失效联动与受保护写操作在并发下结论确定。
    判定优先级（会话级状态优先于凭据级状态）：
    撤销 > 账号失效 > 已轮换 > 已过期。
    """

    def __init__(
        self,
        account_store: AccountStore,
        ttl_seconds: float = 300.0,
        max_lifetime_seconds: float = 3600.0,
        clock: Callable[[], float] = None,
    ):
        self._accounts = account_store
        self._ttl = ttl_seconds
        self._max_lifetime = max_lifetime_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        # 所有签发过的凭据 -> 会话，用于区分"从未存在"与"已轮换"。
        self._token_index: dict[str, str] = {}
        self._rotated_tokens: set[str] = set()

    # ---- 内部：须在持锁状态下调用 ----

    def _resolve_locked(self, token: str) -> tuple[Decision, Optional[Session]]:
        """凭据定位与会话级状态检查（不含过期），供 validate/refresh 复用。"""
        session_id = self._token_index.get(token)
        if session_id is None:
            return Decision.deny(DenialReason.SESSION_NOT_FOUND, "凭据从未签发"), None
        session = self._sessions[session_id]
        if session.revoked:
            return Decision.deny(DenialReason.SESSION_REVOKED, "会话已撤销"), None
        account = self._accounts.get_account(session.user_id)
        if account is None or account.epoch != session.account_epoch:
            return Decision.deny(
                DenialReason.SESSION_INVALIDATED, "账号状态已变化，会话被强制失效"
            ), None
        if token in self._rotated_tokens:
            return Decision.deny(DenialReason.TOKEN_ROTATED, "凭据已被轮换"), None
        return Decision.allow("凭据定位成功"), session

    def _check_locked(self, token: str) -> tuple[Decision, Optional[Session]]:
        decision, session = self._resolve_locked(token)
        if not decision.allowed:
            return decision, None
        if self._clock() >= session.expires_at:
            return Decision.deny(DenialReason.SESSION_EXPIRED, "会话已过期"), None
        return Decision.allow("凭据有效"), session

    # ---- 公开接口 ----

    def login(self, username: str, password: str) -> tuple[Decision, Optional[Session]]:
        """基于本地账号登录：口令由 AccountStore 校验，角色取自账号本身。"""
        decision, account = self._accounts.authenticate(username, password)
        if not decision.allowed:
            return decision, None
        with self._lock:
            now = self._clock()
            session = Session(
                session_id=uuid.uuid4().hex,
                user_id=account.username,
                role=account.role,
                token=secrets.token_hex(16),
                csrf_token=secrets.token_hex(16),
                expires_at=min(now + self._ttl, now + self._max_lifetime),
                created_at=now,
                account_epoch=account.epoch,
            )
            self._sessions[session.session_id] = session
            self._token_index[session.token] = session.session_id
            return Decision.allow("登录成功"), session

    def validate(self, token: str) -> Decision:
        """校验凭据；过期/已轮换/已撤销/账号失效必须可区分。"""
        with self._lock:
            decision, _ = self._check_locked(token)
            return decision

    def refresh(self, old_token: str) -> tuple[Decision, Optional[Session]]:
        """轮换凭据：旧凭据立即失效，并发重复刷新仅一个成功。

        续期不能突破登录时刻算起的总时长上限：到达上限后明确拒绝，
        上限之前签发的新凭据有效期也不越过上限。
        """
        with self._lock:
            # 续期路径上，总时长上限的判定优先于自然过期，
            # 使"到达上限"与"普通到期"始终可区分。
            decision, session = self._resolve_locked(old_token)
            if not decision.allowed:
                return decision, None
            now = self._clock()
            absolute_deadline = session.created_at + self._max_lifetime
            if now >= absolute_deadline:
                return Decision.deny(
                    DenialReason.SESSION_MAX_AGE_EXCEEDED,
                    f"会话总时长已达上限 {self._max_lifetime:.0f}s，禁止续期",
                ), None
            if now >= session.expires_at:
                return Decision.deny(DenialReason.SESSION_EXPIRED, "会话已过期"), None
            self._rotated_tokens.add(old_token)
            session.token = secrets.token_hex(16)
            session.csrf_token = secrets.token_hex(16)
            session.expires_at = min(now + self._ttl, absolute_deadline)
            session.version += 1
            self._token_index[session.token] = session.session_id
            return Decision.allow("凭据已轮换"), session

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
