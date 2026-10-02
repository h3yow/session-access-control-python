"""本地账号模型：仅使用仓库已有依赖与标准库，不接任何外部服务。

口令使用标准库 pbkdf2_hmac 加盐派生（演示级强度，非真实生产凭据）。
账号还携带角色、启用状态与状态代次 epoch：账号被停用或口令被修改时
epoch 递增，AuthService 据此让此前签发的会话立即失效。
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Optional

from app.models import Role

# 演示用口令派生参数（本地、确定性、无需第三方依赖）。
_PBKDF2_ROUNDS = 200_000
_PBKDF2_ALGO = "sha256"


class AccountStatus(enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass
class Account:
    """一条本地账号记录。password_hash 为 pbkdf2 派生串。"""

    user_id: str
    password_hash: str
    role: Role
    enabled: bool = True
    epoch: int = 0


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """加盐派生口令；返回 'pbkdf2_sha256$rounds$salt_hex$hash_hex'。"""
    if salt is None:
        salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return f"pbkdf2_{_PBKDF2_ALGO}${_PBKDF2_ROUNDS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """常量时间比对口令与已存储的派生串；格式异常时返回 False。"""
    try:
        scheme, rounds_s, salt_hex, _ = stored.split("$", 3)
        if scheme != f"pbkdf2_{_PBKDF2_ALGO}":
            return False
        salt = bytes.fromhex(salt_hex)
        derived = hashlib.pbkdf2_hmac(
            _PBKDF2_ALGO, password.encode("utf-8"), salt, int(rounds_s)
        )
        return hmac.compare_digest(derived.hex(), _.split("$", 1)[0])
    except (ValueError, TypeError):
        return False


class AccountStore:
    """内存账号仓库。线程安全由持有方（AuthService 的锁）保证。"""

    def __init__(self, accounts: Optional[dict[str, Account]] = None):
        self._accounts: dict[str, Account] = dict(accounts or {})

    @staticmethod
    def with_passwords(entries: list[tuple[str, str, Role, bool]]) -> "AccountStore":
        """以 (user_id, 明文口令, 角色, 是否启用) 列表构造仓库（仅本地演示）。"""
        store = AccountStore()
        for user_id, password, role, enabled in entries:
            store.add(
                Account(
                    user_id=user_id,
                    password_hash=hash_password(password),
                    role=role,
                    enabled=enabled,
                )
            )
        return store

    def get(self, user_id: str) -> Optional[Account]:
        return self._accounts.get(user_id)

    def add(self, account: Account) -> None:
        self._accounts[account.user_id] = account

    def set_enabled(self, user_id: str, enabled: bool) -> Account:
        """启用/停用账号；停用时 epoch 递增以联动既有会话失效。"""
        account = self._accounts[user_id]
        account.enabled = enabled
        if not enabled:
            account.epoch += 1
        return account

    def change_password(self, user_id: str, new_password: str) -> Account:
        """修改口令并使 epoch 递增，此前签发的会话立即失效。"""
        account = self._accounts[user_id]
        account.password_hash = hash_password(new_password)
        account.epoch += 1
        return account

    def bump_epoch(self, user_id: str) -> int:
        """账号状态代次递增，返回新代次。"""
        account = self._accounts[user_id]
        account.epoch += 1
        return account.epoch
