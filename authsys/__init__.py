"""登录认证与会话访问控制包。

* :class:`~authsys.service.AuthService`：登录、凭据校验、刷新、撤销、受保护写
* :class:`~authsys.access.AccessControl`：基于角色的资源访问判定
* :class:`~authsys.store.SessionStore`：线程安全的会话存储
* :class:`~authsys.errors.AuthError` / :class:`~authsys.errors.DenyReason`：
  确定且可区分的拒绝原因
"""

from .access import AccessControl
from .errors import AuthError, DenyReason
from .models import (
    AccessDecision,
    Permission,
    RefreshResult,
    Resource,
    Role,
    Session,
    User,
    WriteResult,
)
from .service import AuthService
from .store import SessionStore

__all__ = [
    "AccessControl",
    "AccessDecision",
    "AuthError",
    "AuthService",
    "DenyReason",
    "Permission",
    "RefreshResult",
    "Resource",
    "Role",
    "Session",
    "SessionStore",
    "User",
    "WriteResult",
]
