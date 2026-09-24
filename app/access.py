"""基于角色的资源访问判定。

权限模型（纯函数，不修改任何状态，结论不随请求顺序或并发变化）：

读：
- ADMIN   : 可读任意资源
- OWNER   : 自有资源可读；他人 public 资源可读；他人 private 资源拒绝(NOT_OWNER)
- VIEWER  : 仅 public 资源可读，private 拒绝(FORBIDDEN_ROLE)

写：
- ADMIN   : 可写任意资源
- OWNER   : 仅可写自有资源，否则拒绝(NOT_OWNER)
- VIEWER  : 任何资源都不可写，拒绝(FORBIDDEN_ROLE)
"""
from __future__ import annotations

from app.models import Decision, DenialReason, Resource, Role, Session


def can_read(session: Session, resource: Resource) -> Decision:
    role = session.role
    if role is Role.ADMIN:
        return Decision.allow("管理员可读任意资源")
    if session.user_id == resource.owner_id:
        return Decision.allow("资源所有者可读自有资源")
    if role is Role.OWNER and resource.visibility == "public":
        return Decision.allow("其他所有者可读 public 资源")
    if role is Role.VIEWER and resource.visibility == "public":
        return Decision.allow("查看者可读 public 资源")
    if role is Role.VIEWER:
        return Decision.deny(
            DenialReason.FORBIDDEN_ROLE,
            f"查看者无权读取 private 资源 {resource.resource_id}",
        )
    return Decision.deny(
        DenialReason.NOT_OWNER,
        f"用户 {session.user_id} 不是资源 {resource.resource_id} 的所有者",
    )


def can_write(session: Session, resource: Resource) -> Decision:
    role = session.role
    if role is Role.ADMIN:
        return Decision.allow("管理员可写任意资源")
    if role is Role.OWNER:
        if session.user_id == resource.owner_id:
            return Decision.allow("资源所有者可写自有资源")
        return Decision.deny(
            DenialReason.NOT_OWNER,
            f"用户 {session.user_id} 不是资源 {resource.resource_id} 的所有者",
        )
    return Decision.deny(
        DenialReason.FORBIDDEN_ROLE,
        f"查看者无权写资源 {resource.resource_id}",
    )
