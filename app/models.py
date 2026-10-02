"""类型定义：角色、会话、资源、判定结果与拒绝原因。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Role(enum.Enum):
    """用户角色，能力边界见 access.py。"""

    ADMIN = "admin"
    OWNER = "owner"
    VIEWER = "viewer"


class TokenStatus(enum.Enum):
    """会话凭据生命周期状态。"""

    ACTIVE = "active"
    EXPIRED = "expired"
    ROTATED = "rotated"
    REVOKED = "revoked"


class DenialReason(enum.Enum):
    """所有可区分的拒绝原因。"""

    SESSION_NOT_FOUND = "session_not_found"
    SESSION_EXPIRED = "session_expired"
    TOKEN_ROTATED = "token_rotated"
    SESSION_REVOKED = "session_revoked"
    FORBIDDEN_ROLE = "forbidden_role"
    NOT_OWNER = "not_owner"
    CSRF_MISSING = "csrf_missing"
    CSRF_MISMATCH = "csrf_mismatch"
    VERSION_CONFLICT = "version_conflict"
    # 登录认证
    ACCOUNT_UNKNOWN = "account_unknown"
    PASSWORD_MISMATCH = "password_mismatch"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_LOCKED = "account_locked"
    # 账号状态变化导致的会话失效
    SESSION_INVALIDATED = "session_invalidated"
    # 续期总时长上限
    SESSION_MAX_AGE_EXCEEDED = "session_max_age_exceeded"


@dataclass(frozen=True)
class Decision:
    """一次判定的结论：允许或携带可区分原因的拒绝。"""

    allowed: bool
    reason: Optional[DenialReason] = None
    detail: str = ""

    @staticmethod
    def allow(detail: str = "") -> "Decision":
        return Decision(allowed=True, reason=None, detail=detail)

    @staticmethod
    def deny(reason: DenialReason, detail: str = "") -> "Decision":
        return Decision(allowed=False, reason=reason, detail=detail)


@dataclass
class Session:
    """服务端会话记录。version 用于乐观并发控制。

    created_at 为登录时刻（续期总时长上限的基准）；
    account_epoch 为签发时账号的凭据纪元，账号停用/改密后纪元变化即失效。
    """

    session_id: str
    user_id: str
    role: Role
    token: str
    csrf_token: str
    expires_at: float
    revoked: bool = False
    version: int = 0
    created_at: float = 0.0
    account_epoch: int = 0


@dataclass
class Account:
    """本地账号。口令只保存加盐散列；epoch 在停用或改密时递增。"""

    username: str
    password_hash: str
    salt: str
    role: Role
    enabled: bool = True
    epoch: int = 0


@dataclass
class Resource:
    """受保护资源。visibility: public 任何登录角色可读，private 仅所有者与管理员。"""

    resource_id: str
    owner_id: str
    visibility: str = "private"
    content: str = ""
