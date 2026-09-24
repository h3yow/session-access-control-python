"""核心数据模型：用户、资源、会话、判定结果。"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from .errors import DenyReason


class Role(str, Enum):
    ADMIN = "admin"
    OWNER = "owner"   # 资源所有者（普通用户对自己拥有的资源）
    USER = "user"     # 普通已登录用户
    GUEST = "guest"


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


def new_token() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class User:
    user_id: str
    username: str
    password_hash: str          # 仅本地演示用哈希，不依赖外部服务
    roles: frozenset[Role] = frozenset({Role.USER})


@dataclass(frozen=True)
class Resource:
    resource_id: str
    owner_id: str
    # 资源自身的可见/可写角色策略
    read_roles: frozenset[Role] = frozenset({Role.ADMIN, Role.OWNER, Role.USER})
    write_roles: frozenset[Role] = frozenset({Role.ADMIN, Role.OWNER})
    delete_roles: frozenset[Role] = frozenset({Role.ADMIN, Role.OWNER})


@dataclass
class Session:
    session_id: str
    user_id: str
    token: str                  # 当前有效访问凭据
    proof: str                  # 写操作保护凭据（随刷新一并轮换）
    version: int                # 乐观锁版本号
    issued_at: float
    expires_at: float           # 滑动过期时间
    absolute_expires_at: float  # 绝对过期时间（刷新不能突破）
    revoked: bool = False
    rotated_from: str | None = None  # 若是轮换产生，记录旧 token
    metadata: dict = field(default_factory=dict)

    def is_expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at or now >= self.absolute_expires_at


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    user_id: str
    resource_id: str
    permission: Permission
    reason: DenyReason | None = None
    basis: str = ""             # 判定依据的文字说明，供日志/审计


@dataclass(frozen=True)
class RefreshResult:
    session_id: str
    old_token: str
    new_token: str
    new_proof: str
    version: int


@dataclass(frozen=True)
class WriteResult:
    session_id: str
    version: int
    changed: bool
