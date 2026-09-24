"""会话生命周期管理：登录、校验、刷新轮换、撤销、受保护写操作。"""
from __future__ import annotations

import secrets
import threading
import time
import uuid
from typing import Callable, Optional

from app.models import Decision, DenialReason, Role, Session


class AuthService:
    """内存会话服务。

    并发模型：所有状态读取与变更都在同一把锁内完成，
    因此刷新轮换、撤销与受保护写操作在并发下结论确定。
    判定优先级（会话级状态优先于凭据级状态）：
    撤销 > 已轮换 > 已过期。
    """

    def __init__(self, ttl_seconds: float = 300.0, clock: Callable[[], float] = None):
        self._ttl = ttl_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        # 所有签发过的凭据 -> 会话，用于区分"从未存在"与"已轮换"。
        self._token_index: dict[str, str] = {}
        self._rotated_tokens: set[str] = set()

    # ---- 内部：须在持锁状态下调用 ----

    def _check_locked(self, token: str) -> tuple[Decision, Optional[Session]]:
        session_id = self._token_index.get(token)
        if session_id is None:
            return Decision.deny(DenialReason.SESSION_NOT_FOUND, "凭据从未签发"), None
        session = self._sessions[session_id]
        if session.revoked:
            return Decision.deny(DenialReason.SESSION_REVOKED, "会话已撤销"), None
        if token in self._rotated_tokens:
            return Decision.deny(DenialReason.TOKEN_ROTATED, "凭据已被轮换"), None
        if self._clock() >= session.expires_at:
            return Decision.deny(DenialReason.SESSION_EXPIRED, "会话已过期"), None
        return Decision.allow("凭据有效"), session

    # ---- 公开接口 ----

    def login(self, user_id: str, role: Role) -> Session:
        with self._lock:
            session = Session(
                session_id=uuid.uuid4().hex,
                user_id=user_id,
                role=role,
                token=secrets.token_hex(16),
                csrf_token=secrets.token_hex(16),
                expires_at=self._clock() + self._ttl,
            )
            self._sessions[session.session_id] = session
            self._token_index[session.token] = session.session_id
            return session

    def validate(self, token: str) -> Decision:
        """校验凭据；过期/已轮换/已撤销必须可区分。"""
        with self._lock:
            decision, _ = self._check_locked(token)
            return decision

    def refresh(self, old_token: str) -> tuple[Decision, Optional[Session]]:
        """轮换凭据：旧凭据立即失效，并发重复刷新仅一个成功。"""
        with self._lock:
            decision, session = self._check_locked(old_token)
            if not decision.allowed:
                return decision, None
            self._rotated_tokens.add(old_token)
            session.token = secrets.token_hex(16)
            session.csrf_token = secrets.token_hex(16)
            session.expires_at = self._clock() + self._ttl
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
