"""FastAPI 路由层：本地账号登录、刷新、撤销、账号状态管理、受保护读写。

拒绝响应统一形如 {"allowed": false, "reason": <DenialReason.value>, "detail": ...}，
不同的凭据/权限/保护失败在 HTTP 层依旧可区分（401 认证失败 / 403 权限或保护失败 / 409 版本冲突）。

演示用本地账号全部为假口令，仅用于本地验证，不是真实生产凭据。
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.access import can_manage_accounts, can_read, can_write
from app.accounts import AccountStore
from app.auth import AuthService
from app.models import DenialReason, Resource, Role

app = FastAPI(title="session-access-control")

# 演示用本地账号（假口令），角色由账号决定，登录请求不能自选角色。
accounts = AccountStore(max_failures=3, lockout_seconds=30.0)
accounts.add_account("alice", "alice-pw", Role.OWNER)
accounts.add_account("bob", "bob-pw", Role.OWNER)
accounts.add_account("carol", "carol-pw", Role.VIEWER)
accounts.add_account("root", "root-pw", Role.ADMIN)
accounts.add_account("dave", "dave-pw", Role.VIEWER, enabled=False)

auth = AuthService(accounts, ttl_seconds=300.0, max_lifetime_seconds=1800.0)

# 演示用本地数据，不依赖任何外部服务。
_resources: dict[str, Resource] = {
    "r-public": Resource("r-public", owner_id="alice", visibility="public", content="公开资料"),
    "r-alice": Resource("r-alice", owner_id="alice", visibility="private", content="Alice 私有"),
    "r-bob": Resource("r-bob", owner_id="bob", visibility="private", content="Bob 私有"),
}


class LoginBody(BaseModel):
    username: str
    password: str


class PasswordBody(BaseModel):
    new_password: str


class NoteBody(BaseModel):
    note: str
    csrf_token: str
    expected_version: Optional[int] = None


class ResourceBody(BaseModel):
    content: str
    csrf_token: str


def _deny_http(reason: DenialReason, detail: str) -> HTTPException:
    # 401：凭据/账号认证类失败；403：权限/保护信息失败；409：乐观版本冲突。
    if reason in (
        DenialReason.SESSION_NOT_FOUND,
        DenialReason.SESSION_EXPIRED,
        DenialReason.TOKEN_ROTATED,
        DenialReason.SESSION_REVOKED,
        DenialReason.SESSION_INVALIDATED,
        DenialReason.SESSION_MAX_AGE_EXCEEDED,
        DenialReason.ACCOUNT_UNKNOWN,
        DenialReason.PASSWORD_MISMATCH,
        DenialReason.ACCOUNT_DISABLED,
        DenialReason.ACCOUNT_LOCKED,
    ):
        status = 401
    elif reason is DenialReason.VERSION_CONFLICT:
        status = 409
    else:
        status = 403
    return HTTPException(status_code=status, detail={"allowed": False, "reason": reason.value, "detail": detail})


def _session_view(session) -> dict:
    return {
        "allowed": True,
        "session_id": session.session_id,
        "user_id": session.user_id,
        "role": session.role.value,
        "token": session.token,
        "csrf_token": session.csrf_token,
        "expires_at": session.expires_at,
        "version": session.version,
    }


def _require_admin(x_auth_token: Optional[str]):
    """账号管理操作的守卫：必须已登录且具备 admin 角色。

    拒绝原因可区分：未携带/无效凭据 -> 401（session_not_found 等），
    已登录但角色不足 -> 403 forbidden_role。
    """
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")
    decision = auth.validate(x_auth_token)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    session = auth.get_active_session(x_auth_token)
    access = can_manage_accounts(session)
    if not access.allowed:
        raise _deny_http(access.reason, access.detail)
    return session


@app.post("/login")
def login(body: LoginBody):
    decision, session = auth.login(body.username, body.password)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return _session_view(session)


@app.post("/refresh")
def refresh(x_auth_token: Optional[str] = Header(default=None)):
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")
    decision, session = auth.refresh(x_auth_token)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return _session_view(session)


@app.post("/revoke/{session_id}")
def revoke(session_id: str):
    decision = auth.revoke(session_id)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.post("/accounts/{username}/disable")
def disable_account(username: str, x_auth_token: Optional[str] = Header(default=None)):
    """停用账号（仅 admin）：该账号既有会话全部立即失效（session_invalidated）。"""
    _require_admin(x_auth_token)
    decision = accounts.set_enabled(username, False)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.post("/accounts/{username}/password")
def change_password(
    username: str, body: PasswordBody, x_auth_token: Optional[str] = Header(default=None)
):
    """修改口令（仅 admin）：该账号既有会话全部立即失效（session_invalidated）。"""
    _require_admin(x_auth_token)
    decision = accounts.change_password(username, body.new_password)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.get("/resource/{resource_id}")
def read_resource(resource_id: str, x_auth_token: Optional[str] = Header(default=None)):
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")
    decision = auth.validate(x_auth_token)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    # validate 已确认有效，直接通过会话仓库读取当前会话。
    session = auth.get_active_session(x_auth_token)
    resource = _resources.get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="资源不存在")
    access = can_read(session, resource)
    if not access.allowed:
        raise _deny_http(access.reason, access.detail)
    return {"allowed": True, "resource_id": resource.resource_id, "content": resource.content}


@app.put("/resource/{resource_id}")
def write_resource(
    resource_id: str,
    body: ResourceBody,
    x_auth_token: Optional[str] = Header(default=None),
):
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")
    decision = auth.validate(x_auth_token)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    session = auth.get_active_session(x_auth_token)
    if body.csrf_token != session.csrf_token:
        raise _deny_http(DenialReason.CSRF_MISMATCH, "保护信息不匹配")
    resource = _resources.get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="资源不存在")
    access = can_write(session, resource)
    if not access.allowed:
        raise _deny_http(access.reason, access.detail)
    resource.content = body.content
    return {"allowed": True, "resource_id": resource.resource_id, "content": resource.content}


@app.post("/session/note")
def update_note(body: NoteBody, x_auth_token: Optional[str] = Header(default=None)):
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")

    def _set_note(session):
        session.note = body.note  # type: ignore[attr-defined]

    decision = auth.update_session(
        x_auth_token, body.csrf_token, body.expected_version, _set_note
    )
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    session = auth.get_active_session(x_auth_token)
    return {"allowed": True, "note": getattr(session, "note", None), "version": session.version}
