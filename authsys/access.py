"""基于角色的资源访问判定（RBAC）。

判定是纯函数式的：只依赖“用户角色 + 资源所有者 + 资源策略”，
不修改任何状态，因此结论与请求顺序、并发无关，永远可复现。

角色能力边界：

* ``ADMIN``：对所有资源隐式拥有 read/write/delete（由策略表显式声明，
  不做代码内特例），但不因此成为资源所有者；
* ``OWNER``：不是用户的全局角色，而是当 ``user.user_id ==
  resource.owner_id`` 时派生出的“对该资源”的角色；
* ``USER``：默认可读，写/删取决于资源策略；
* ``GUEST``：仅当资源策略显式允许时才可读。
"""

from __future__ import annotations

import logging

from .errors import DenyReason
from .models import (
    AccessDecision,
    Permission,
    Resource,
    Role,
    User,
)
from .service import AuthService

logger = logging.getLogger("authsys.access")

_PERMISSION_POLICY_ATTR = {
    Permission.READ: "read_roles",
    Permission.WRITE: "write_roles",
    Permission.DELETE: "delete_roles",
}


class AccessControl:
    def __init__(self, auth: AuthService) -> None:
        self.auth = auth
        self._users: dict[str, User] = {}
        self._resources: dict[str, Resource] = {}

    def add_user(self, user: User) -> None:
        self._users[user.user_id] = user
        # 用户同时登记到认证服务，便于登录
        self.auth.register_user(user)

    def add_resource(self, resource: Resource) -> None:
        self._resources[resource.resource_id] = resource

    def effective_roles(self, user: User, resource: Resource) -> frozenset[Role]:
        """用户对某资源的实际角色集合（含 OWNER 派生）。"""
        roles = set(user.roles)
        if user.user_id == resource.owner_id:
            roles.add(Role.OWNER)
        return frozenset(roles)

    def decide(
        self,
        token: str,
        resource_id: str,
        permission: Permission,
    ) -> AccessDecision:
        """返回确定的判定结果；凭据问题以 :class:`AuthError` 抛出。

        权限不足不抛异常，而返回 ``allowed=False`` 的决策，
        其中 ``basis`` 保留判定依据（命中角色 / 缺失角色）。
        """
        logger.info(
            "access request token=%.8s resource=%s permission=%s",
            token, resource_id, permission.value,
        )

        # 1. 凭据校验（原因可区分：过期/轮换/撤销/不存在）
        session = self.auth.authenticate(token)
        user = self._users.get(session.user_id)
        if user is None:
            d = AccessDecision(
                allowed=False, user_id=session.user_id,
                resource_id=resource_id, permission=permission,
                reason=DenyReason.ACCESS_DENIED_ROLE,
                basis="authenticated user is not registered in policy store",
            )
            logger.warning("access denied basis=%s", d.basis)
            return d

        # 2. 资源存在性
        resource = self._resources.get(resource_id)
        if resource is None:
            d = AccessDecision(
                allowed=False, user_id=user.user_id,
                resource_id=resource_id, permission=permission,
                reason=DenyReason.RESOURCE_NOT_FOUND,
                basis="resource not present in resource registry",
            )
            logger.warning("access denied reason=%s basis=%s", d.reason.value, d.basis)
            return d

        # 3. 纯角色判定
        roles = self.effective_roles(user, resource)
        attr = _PERMISSION_POLICY_ATTR[permission]
        allowed_roles: frozenset[Role] = getattr(resource, attr)
        hit = roles & allowed_roles

        if hit:
            basis = (
                f"roles={sorted(r.value for r in roles)} "
                f"{permission.value}_roles={sorted(r.value for r in allowed_roles)} "
                f"hit={sorted(r.value for r in hit)}"
            )
            d = AccessDecision(
                allowed=True, user_id=user.user_id,
                resource_id=resource_id, permission=permission, basis=basis,
            )
            logger.info("access allowed basis=%s", basis)
            return d

        basis = (
            f"roles={sorted(r.value for r in roles)} "
            f"{permission.value}_roles={sorted(r.value for r in allowed_roles)} "
            f"hit=<none>; ownership={user.user_id == resource.owner_id}"
        )
        d = AccessDecision(
            allowed=False, user_id=user.user_id,
            resource_id=resource_id, permission=permission,
            reason=DenyReason.ACCESS_DENIED_ROLE, basis=basis,
        )
        logger.warning(
            "access denied reason=%s basis=%s",
            DenyReason.ACCESS_DENIED_ROLE.value, basis,
        )
        return d
