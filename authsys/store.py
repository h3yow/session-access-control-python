"""线程安全的会话存储。

所有对会话表、token 索引、死信表的读写都在同一把可重入锁内完成，
保证认证、刷新、撤销、乐观写之间的互斥与可见性。
"""

from __future__ import annotations

import threading

from .errors import DenyReason
from .models import Session


class SessionStore:
    """基于 token 索引的会话存储。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}   # session_id -> session
        self._token_index: dict[str, str] = {}    # token -> session_id
        # 已轮换/失效的旧 token -> DenyReason 值，永久保留（演示进程内），
        # 保证旧凭据重放时得到确定且可区分的结论。
        self._dead_tokens: dict[str, str] = {}
        # 随刷新被轮换掉的旧保护凭据 -> 拒绝原因（PROOF_EXPIRED）
        self._dead_proofs: dict[str, str] = {}

    @property
    def lock(self) -> threading.RLock:
        """供上层服务在同一临界区完成“检查 + 更新”。"""
        return self._lock

    def put(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
            self._token_index[session.token] = session.session_id

    def replace(
        self,
        old: Session,
        new: Session,
        obsolete_token: str | None = None,
    ) -> None:
        """整体替换会话对象。

        旧对象保持原样（调用方手中的快照不会被改写）；
        ``obsolete_token`` 若与新 token 不同，则从索引中摘除。
        """
        with self._lock:
            self._sessions[new.session_id] = new
            if obsolete_token is not None and obsolete_token != new.token:
                self._token_index.pop(obsolete_token, None)
            self._token_index[new.token] = new.session_id

    def get_by_token(self, token: str) -> Session | None:
        with self._lock:
            sid = self._token_index.get(token)
            if sid is None:
                return None
            return self._sessions.get(sid)

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def mark_dead(self, token: str, reason: DenyReason) -> None:
        with self._lock:
            # 已登记的原因不被覆盖：例如“已轮换”优先于后续“已过期”
            self._dead_tokens.setdefault(token, reason.value)

    def dead_reason(self, token: str) -> DenyReason | None:
        with self._lock:
            val = self._dead_tokens.get(token)
            return DenyReason(val) if val is not None else None

    def mark_proof_dead(self, proof: str, reason: DenyReason) -> None:
        with self._lock:
            self._dead_proofs.setdefault(proof, reason.value)

    def dead_proof_reason(self, proof: str) -> DenyReason | None:
        with self._lock:
            val = self._dead_proofs.get(proof)
            return DenyReason(val) if val is not None else None

    def revoke(self, session_id: str) -> bool:
        """标记撤销；返回本次调用是否发生了状态变更。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked:
                return False
            session.revoked = True
            # 当前 token / proof 立即不可用，并给出确定的“已撤销”结论
            self.mark_dead(session.token, DenyReason.SESSION_REVOKED)
            self.mark_proof_dead(session.proof, DenyReason.SESSION_REVOKED)
            self._token_index.pop(session.token, None)
            return True

    def all_sessions(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())
