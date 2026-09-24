"""认证与会话生命周期服务。

关键并发保证：

* ``refresh`` 在存储的同一把锁内完成“取会话 → 校验版本 → 生成新凭据
  → 摘除旧索引 → 落库”，并发重复刷新只有一个成功，其余抛
  ``REFRESH_CONFLICT``；
* 旧 token 立即进入死信表并登记 ``SESSION_ROTATED``，旧凭据重放永远
  得到同一个确定结论；
* ``protected_write`` 先做全部校验再调用变更函数，任何拒绝都不产生
  状态变更；乐观版本号保证并发更新不丢失。
"""

from __future__ import annotations

import dataclasses
import logging
import time
import uuid
from collections.abc import Callable

from .errors import AuthError, DenyReason
from .models import (
    RefreshResult,
    Session,
    User,
    WriteResult,
    new_token,
)
from .security import verify_password
from .store import SessionStore

logger = logging.getLogger("authsys.service")


class AuthService:
    def __init__(
        self,
        store: SessionStore,
        ttl_seconds: float = 900.0,
        absolute_ttl_seconds: float = 8 * 3600.0,
    ) -> None:
        self.store = store
        self.ttl_seconds = ttl_seconds
        self.absolute_ttl_seconds = absolute_ttl_seconds
        self._users: dict[str, User] = {}

    # ------------------------------------------------------------------ 用户

    def register_user(self, user: User) -> None:
        self._users[user.user_id] = user

    def _find_by_username(self, username: str) -> User | None:
        for user in self._users.values():
            if user.username == username:
                return user
        return None

    # ------------------------------------------------------------------ 登录

    def login(self, username: str, password: str) -> Session:
        logger.info("login request username=%r", username)
        user = self._find_by_username(username)
        if user is None or not verify_password(password, user.password_hash):
            logger.warning(
                "login denied username=%r reason=%s basis=username_or_password_mismatch",
                username, DenyReason.INVALID_CREDENTIALS.value,
            )
            raise AuthError(
                DenyReason.INVALID_CREDENTIALS,
                "username not found or password mismatch",
            )

        now = time.time()
        session = Session(
            session_id=uuid.uuid4().hex,
            user_id=user.user_id,
            token=new_token(),
            proof=new_token(),
            version=1,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            absolute_expires_at=now + self.absolute_ttl_seconds,
        )
        self.store.put(session)
        logger.info(
            "login granted username=%r session_id=%s version=%d",
            username, session.session_id, session.version,
        )
        return session

    # -------------------------------------------------------------- 凭据校验

    def _classify_token(self, token: str, *, for_refresh: bool) -> Session:
        """在锁内对一个 token 给出确定结论。

        优先级：死信登记（轮换/撤销）> 活索引会话（撤销/过期）> 不存在。
        所有分支都抛出可区分的 :class:`AuthError` 或返回活会话。
        """
        store = self.store
        with store.lock:
            dead = store.dead_reason(token)
            session = store.get_by_token(token)

            if dead is not None:
                # 已轮换 / 已撤销的凭据，无论会话本身状态如何，结论固定
                logger.info(
                    "token rejected reason=%s basis=token_recorded_as_%s",
                    dead.value, dead.value,
                )
                raise AuthError(dead, f"token is {dead.value}")

            if session is None:
                logger.info(
                    "token rejected reason=%s basis=no_live_session_for_token",
                    DenyReason.SESSION_NOT_FOUND.value,
                )
                raise AuthError(
                    DenyReason.SESSION_NOT_FOUND, "no live session for token",
                )

            if session.revoked:
                logger.info(
                    "token rejected reason=%s basis=session_revoked_flag",
                    DenyReason.SESSION_REVOKED.value,
                )
                raise AuthError(DenyReason.SESSION_REVOKED, "session revoked")

            now = time.time()
            if session.is_expired(now):
                which = (
                    "absolute_ttl" if now >= session.absolute_expires_at
                    else "sliding_ttl"
                )
                logger.info(
                    "token rejected reason=%s basis=expired_by_%s",
                    DenyReason.SESSION_EXPIRED.value, which,
                )
                raise AuthError(
                    DenyReason.SESSION_EXPIRED, f"session expired ({which})",
                )

            return session

    def authenticate(self, token: str) -> Session:
        """校验访问凭据；失败抛 :class:`AuthError`。"""
        return self._classify_token(token, for_refresh=False)

    # ------------------------------------------------------------------ 刷新

    def refresh(
        self,
        old_token: str,
        expected_version: int | None = None,
    ) -> RefreshResult:
        """用旧凭据换新凭据。

        * 旧凭据必须当前有效（非轮换/撤销/过期）；
        * 整段临界区内完成版本检查与替换，并发刷新只有一个胜出；
        * 刷新延长滑动有效期，但不突破绝对有效期；
        * 旧 token 与旧 proof 立即失效并登记确定原因。
        """
        with self.store.lock:
            session = self._classify_token(old_token, for_refresh=True)

            # 乐观版本：调用方可带上它看到的版本；不匹配说明已被并发刷新
            if expected_version is not None and expected_version != session.version:
                logger.warning(
                    "refresh denied session_id=%s reason=%s "
                    "basis=expected_version_%d_actual_%d",
                    session.session_id, DenyReason.REFRESH_CONFLICT.value,
                    expected_version, session.version,
                )
                raise AuthError(
                    DenyReason.REFRESH_CONFLICT,
                    f"expected version {expected_version}, actual {session.version}",
                )

            now = time.time()
            if now >= session.absolute_expires_at:
                # _classify_token 已拦，这里是双保险
                raise AuthError(DenyReason.SESSION_EXPIRED, "absolute ttl reached")

            fresh_token = new_token()
            fresh_proof = new_token()
            new_version = session.version + 1
            new_expires = min(now + self.ttl_seconds, session.absolute_expires_at)

            # 1) 旧凭据立即入死信表（轮换优先）
            self.store.mark_dead(old_token, DenyReason.SESSION_ROTATED)
            # 当前会话持有的 proof 同步作废（含登录后第一代 proof）。
            self.store.mark_proof_dead(session.proof, DenyReason.PROOF_EXPIRED)
            # 2) 以全新对象整体替换：调用方手里的旧 Session 快照保持不变，
            #    旧 token 索引在 replace 内摘除，不存在两个并存有效会话。
            new_session = Session(
                session_id=session.session_id,
                user_id=session.user_id,
                token=fresh_token,
                proof=fresh_proof,
                version=new_version,
                issued_at=session.issued_at,
                expires_at=new_expires,
                absolute_expires_at=session.absolute_expires_at,
                revoked=False,
                rotated_from=old_token,
                metadata=dict(session.metadata),
            )
            self.store.replace(session, new_session, obsolete_token=old_token)

            logger.info(
                "refresh granted session_id=%s version_%d->%d basis=single_winner",
                session.session_id, new_version - 1, new_version,
            )
            return RefreshResult(
                session_id=session.session_id,
                old_token=old_token,
                new_token=fresh_token,
                new_proof=fresh_proof,
                version=new_version,
            )

    # ------------------------------------------------------------------ 撤销

    def logout(self, token: str) -> None:
        """登出：要求凭据当前有效；撤销后凭据立即不可用。"""
        with self.store.lock:
            # 已死信的凭据直接返回其确定原因，不允许“再登出一次”掩盖结论
            dead = self.store.dead_reason(token)
            if dead is not None:
                raise AuthError(dead, f"token already {dead.value}")
            session = self.store.get_by_token(token)
            if session is None:
                raise AuthError(
                    DenyReason.SESSION_NOT_FOUND, "no live session for token",
                )
            self.store.revoke(session.session_id)
            logger.info(
                "logout granted session_id=%s basis=explicit_revoke",
                session.session_id,
            )

    def revoke_session(self, session_id: str) -> bool:
        """管理员吊销：按 session_id 显式撤销，返回是否发生状态变更。"""
        with self.store.lock:
            session = self.store.get(session_id)
            if session is None:
                return False
            changed = self.store.revoke(session_id)
            if changed:
                logger.info(
                    "admin revoke granted session_id=%s basis=explicit_revoke",
                    session_id,
                )
            return changed

    # ------------------------------------------------------------ 受保护写

    def protected_write(
        self,
        token: str,
        proof: str | None,
        expected_version: int,
        mutate: Callable[[Session], None],
    ) -> WriteResult:
        """带保护凭据与乐观版本号的会话写操作。

        拒绝原因可区分：``PROOF_MISSING / PROOF_MISMATCH / PROOF_EXPIRED /
        VERSION_CONFLICT`` 以及各类凭据错误。被拒绝时 ``mutate`` 绝不会
        被调用，因此不产生任何状态变更。
        """
        logger.info(
            "protected_write request expected_version=%d proof_present=%s",
            expected_version, proof is not None,
        )
        with self.store.lock:
            session = self._classify_token(token, for_refresh=False)

            # 保护凭据校验
            if proof is None or proof == "":
                logger.warning(
                    "write denied session_id=%s reason=%s basis=no_proof_supplied",
                    session.session_id, DenyReason.PROOF_MISSING.value,
                )
                raise AuthError(DenyReason.PROOF_MISSING, "proof is required")

            if self.store.dead_proof_reason(proof) is not None:
                logger.warning(
                    "write denied session_id=%s reason=%s "
                    "basis=proof_rotated_or_revoked",
                    session.session_id, DenyReason.PROOF_EXPIRED.value,
                )
                raise AuthError(
                    DenyReason.PROOF_EXPIRED,
                    "proof was rotated or revoked with an older session",
                )

            if proof != session.proof:
                logger.warning(
                    "write denied session_id=%s reason=%s basis=proof_not_equal",
                    session.session_id, DenyReason.PROOF_MISMATCH.value,
                )
                raise AuthError(DenyReason.PROOF_MISMATCH, "proof does not match")

            # 乐观版本号校验（在所有其它校验之后、任何变更之前）
            if expected_version != session.version:
                logger.warning(
                    "write denied session_id=%s reason=%s "
                    "basis=expected_version_%d_actual_%d",
                    session.session_id,
                    DenyReason.VERSION_CONFLICT.value,
                    expected_version, session.version,
                )
                raise AuthError(
                    DenyReason.VERSION_CONFLICT,
                    f"expected version {expected_version}, actual {session.version}",
                )

            # 全部通过：在一份全新副本上执行变更，再整体替换；
            # 被拒绝路径从不执行 mutate，也从不触碰已存储对象。
            updated = dataclasses.replace(session, metadata=dict(session.metadata))
            mutate(updated)
            updated.version = session.version + 1
            self.store.replace(session, updated)
            result = WriteResult(
                session_id=updated.session_id,
                version=updated.version,
                changed=True,
            )
            logger.info(
                "write granted session_id=%s new_version=%d",
                updated.session_id, updated.version,
            )
            return result
