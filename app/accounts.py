"""本地账号存储：口令校验、登录失败限流锁定、账号状态管理。

判定语义（authenticate 内按序判定，全部在同一把锁内完成）：
1. 账号不存在            -> account_unknown（不计入失败次数）
2. 正处于锁定期          -> account_locked（即使口令正确也拒绝，且不计数、不延长锁定）
3. 账号被停用            -> account_disabled
4. 口令不匹配            -> password_mismatch，失败计数 +1；
   连续失败达到上限后进入锁定期，计数清零
5. 全部通过              -> 允许，失败计数与锁定状态清零

口令只保存 PBKDF2 加盐散列，比较使用恒定时间比较。
账号停用/启用、修改口令都会递增 epoch，供会话层检测"账号状态变化"。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from typing import Callable, Optional

from app.models import Account, AccountSnapshot, Decision, DenialReason, Role

_PBKDF2_ITERATIONS = 100_000


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()


class AccountStore:
    """内存账号仓库。

    并发模型：认证、失败计数、锁定与状态变更都在同一把锁内完成，
    并发登录失败不会少算次数，锁定判定也不会因并发而多放行。

    可通过构造参数注入与 AuthService **共享的同一把 RLock**：
    这样"认证 → 会话签发"与"停用/改密"在全局同一临界区内串行，
    状态切换完成后不可能再签出或续出任何可用会话。
    """

    def __init__(
        self,
        max_failures: int = 5,
        lockout_seconds: float = 60.0,
        clock: Callable[[], float] = None,
        lock: Optional[threading.RLock] = None,
    ):
        # RLock：AuthService 持锁后会回调本仓库的方法（如 get_account），需要可重入。
        self._lock = lock or threading.RLock()
        self._accounts: dict[str, Account] = {}
        self._failures: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._clock = clock or time.monotonic

    @property
    def lock(self) -> threading.RLock:
        """与会话服务共享的临界区锁。"""
        return self._lock

    # ---- 内部：须在持锁状态下调用 ----

    def _reset_throttle_locked(self, username: str) -> None:
        self._failures.pop(username, None)
        self._locked_until.pop(username, None)

    # ---- 账号管理 ----

    def add_account(self, username: str, password: str, role: Role, enabled: bool = True) -> None:
        with self._lock:
            salt = secrets.token_hex(16)
            self._accounts[username] = Account(
                username=username,
                password_hash=_hash_password(password, salt),
                salt=salt,
                role=role,
                enabled=enabled,
            )

    def get_account(self, username: str) -> Optional[Account]:
        with self._lock:
            return self._get_account_locked(username)

    def _get_account_locked(self, username: str) -> Optional[Account]:
        return self._accounts.get(username)

    def set_enabled(self, username: str, enabled: bool) -> Decision:
        """停用/启用账号。状态变化会递增 epoch 使既有会话失效；启用时清除限流状态。"""
        with self._lock:
            account = self._accounts.get(username)
            if account is None:
                return Decision.deny(DenialReason.ACCOUNT_UNKNOWN, f"账号 {username} 不存在")
            if account.enabled != enabled:
                account.enabled = enabled
                account.epoch += 1
            if enabled:
                self._reset_throttle_locked(username)
            return Decision.allow(f"账号 {username} 已{'启用' if enabled else '停用'} (epoch={account.epoch})")

    def change_password(self, username: str, new_password: str) -> Decision:
        """修改口令：更新散列、递增 epoch 使既有会话失效、清除限流状态。"""
        with self._lock:
            account = self._accounts.get(username)
            if account is None:
                return Decision.deny(DenialReason.ACCOUNT_UNKNOWN, f"账号 {username} 不存在")
            account.salt = secrets.token_hex(16)
            account.password_hash = _hash_password(new_password, account.salt)
            account.epoch += 1
            self._reset_throttle_locked(username)
            return Decision.allow(f"账号 {username} 口令已修改 (epoch={account.epoch})")

    # ---- 认证 ----

    def authenticate(
        self, username: str, password: str
    ) -> tuple[Decision, Optional[AccountSnapshot]]:
        """校验口令并做失败限流。

        成功时在同一临界区内返回账号快照（username/role/enabled/epoch 定格），
        调用方签发会话必须使用快照，禁止重新读取账号。
        """
        with self._lock:
            return self._authenticate_locked(username, password)

    def _authenticate_locked(
        self, username: str, password: str
    ) -> tuple[Decision, Optional[AccountSnapshot]]:
        """锁内版本：供已持有共享锁的会话服务直接调用，保证认证+签发原子。"""
        account = self._accounts.get(username)
        if account is None:
            return Decision.deny(DenialReason.ACCOUNT_UNKNOWN, f"账号 {username} 不存在"), None
        now = self._clock()
        locked_until = self._locked_until.get(username, 0.0)
        if now < locked_until:
            return Decision.deny(
                DenialReason.ACCOUNT_LOCKED,
                f"账号 {username} 已锁定，剩余 {locked_until - now:.1f}s",
            ), None
        if not account.enabled:
            return Decision.deny(DenialReason.ACCOUNT_DISABLED, f"账号 {username} 已停用"), None
        if not hmac.compare_digest(account.password_hash, _hash_password(password, account.salt)):
            failures = self._failures.get(username, 0) + 1
            if failures >= self._max_failures:
                self._locked_until[username] = now + self._lockout_seconds
                self._failures.pop(username, None)
                return Decision.deny(
                    DenialReason.PASSWORD_MISMATCH,
                    f"口令不匹配，连续失败 {failures} 次，账号锁定 {self._lockout_seconds:.0f}s",
                ), None
            self._failures[username] = failures
            return Decision.deny(
                DenialReason.PASSWORD_MISMATCH,
                f"口令不匹配（第 {failures}/{self._max_failures} 次）",
            ), None
        self._reset_throttle_locked(username)
        # 定格快照：此后即使账号被停用/改密，本次登录的结论也只代表此刻状态。
        snapshot = AccountSnapshot(
            username=account.username,
            role=account.role,
            enabled=account.enabled,
            epoch=account.epoch,
        )
        return Decision.allow("认证通过"), snapshot
