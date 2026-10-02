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
    # 账号级状态（本地账号登录 / 限流 / 账号状态联动）。
    ACCOUNT_NOT_FOUND = "account_not_found"
    BAD_PASSWORD = "bad_password"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_LOCKED = "account_locked"
    # 账号被停用或口令被修改后，此前签发的会话统一失效，须与撤销/过期区分。
    ACCOUNT_STATE_CHANGED = "account_state_changed"
    # 会话达到从登录时刻起算的总时长上限（绝对上限）。
    SESSION_LIFETIME_EXCEEDED = "session_lifetime_exceeded"
    FORBIDDEN_ROLE = "forbidden_role"
    NOT_OWNER = "not_owner"
    CSRF_MISSING = "csrf_missing"
    CSRF_MISMATCH = "csrf_mismatch"
    VERSION_CONFLICT = "version_conflict"


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

    epoch：签发时账号的状态代次；账号被停用或口令被修改时账号代次递增，
    代次落后的旧会话立即失效（ACCOUNT_STATE_CHANGED）。
    absolute_expires_at：从登录时刻起算的总时长上限（绝对上限），
    无论刷新多少次都不会突破；expires_at 为滑动过期时间。
    """

    session_id: str
    user_id: str
    role: Role
    token: str
    csrf_token: str
    expires_at: float
    absolute_expires_at: float
    epoch: int = 0
    revoked: bool = False
    version: int = 0


@dataclass
class Resource:
    """受保护资源。visibility: public 任何登录角色可读，private 仅所有者与管理员。

    content 可变：有权限的写操作会直接更新内容。
    """

    resource_id: str
    owner_id: str
    visibility: str = "private"
    content: str = ""
