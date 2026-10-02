"""FastAPI 路由层：本地账号登录、刷新、撤销、账号状态联动、受保护读写。

拒绝响应统一形如 {"allowed": false, "reason": <DenialReason.value>, "detail": ...}，
不同的凭据/账号/权限/保护失败在 HTTP 层依旧可区分（401 认证或账号失败 /
403 权限或保护失败 / 409 版本冲突）。
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.access import can_read, can_write
from app.auth import AuthService
from app.models import DenialReason, Resource, Role

app = FastAPI(title="session-access-control")

auth = AuthService(ttl_seconds=300.0)

# 演示用本地数据，不依赖任何外部服务。
_resources: dict[str, Resource] = {
    "r-public": Resource("r-public", owner_id="alice", visibility="public", content="公开资料"),
    "r-alice": Resource("r-alice", owner_id="alice", visibility="private", content="Alice 私有"),
    "r-bob": Resource("r-bob", owner_id="bob", visibility="private", content="Bob 私有"),
}

_AUTH_FAILURES = {
    DenialReason.SESSION_NOT_FOUND,
    DenialReason.SESSION_EXPIRED,
    DenialReason.TOKEN_ROTATED,
    DenialReason.SESSION_REVOKED,
    DenialReason.ACCOUNT_NOT_FOUND,
    DenialReason.BAD_PASSWORD,
    DenialReason.ACCOUNT_DISABLED,
    DenialReason.ACCOUNT_LOCKED,
    DenialReason.ACCOUNT_STATE_CHANGED,
    DenialReason.SESSION_LIFETIME_EXCEEDED,
}


class LoginBody(BaseModel):
    # 角色由本地账号决定，请求方不能自行指定。
    user_id: str
    password: str


class NoteBody(BaseModel):
    note: str
    csrf_token: str
    expected_version: Optional[int] = None


class ResourceBody(BaseModel):
    content: str
    csrf_token: str


class PasswordBody(BaseModel):
    new_password: str
    csrf_token: str


def _deny_http(reason: DenialReason, detail: str) -> HTTPException:
    # 401：凭据/账号认证类失败；403：权限/保护信息失败；409：乐观版本冲突。
    if reason in _AUTH_FAILURES:
        status = 401
    elif reason is DenialReason.VERSION_CONFLICT:
        status = 409
    else:
        status = 403
    return HTTPException(status_code=status, detail={"allowed": False, "reason": reason.value, "detail": detail})


def _require_session(x_auth_token: Optional[str]):
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")
    decision = auth.validate(x_auth_token)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    session = auth.get_active_session(x_auth_token)
    return session, x_auth_token


def _require_admin(x_auth_token: Optional[str]):
    session, _ = _require_session(x_auth_token)
    if session.role is not Role.ADMIN:
        raise _deny_http(
            DenialReason.FORBIDDEN_ROLE,
            f"账号 {session.user_id} 角色 {session.role.value} 无权管理账号",
        )
    return session


@app.post("/login")
def login(body: LoginBody):
    decision, session = auth.login(body.user_id, body.password)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {
        "allowed": True,
        "session_id": session.session_id,
        "user_id": session.user_id,
        "role": session.role.value,
        "token": session.token,
        "csrf_token": session.csrf_token,
        "expires_at": session.expires_at,
        "absolute_expires_at": session.absolute_expires_at,
        "version": session.version,
    }


@app.post("/refresh")
def refresh(x_auth_token: Optional[str] = Header(default=None)):
    if not x_auth_token:
        raise _deny_http(DenialReason.SESSION_NOT_FOUND, "缺少凭据")
    decision, session = auth.refresh(x_auth_token)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {
        "allowed": True,
        "session_id": session.session_id,
        "token": session.token,
        "csrf_token": session.csrf_token,
        "expires_at": session.expires_at,
        "absolute_expires_at": session.absolute_expires_at,
        "version": session.version,
    }


@app.post("/revoke/{session_id}")
def revoke(session_id: str):
    decision = auth.revoke(session_id)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.post("/admin/accounts/{user_id}/disable")
def admin_disable(user_id: str, x_auth_token: Optional[str] = Header(default=None)):
    """管理员停用账号：该账号既有会话立即失效。"""
    _require_admin(x_auth_token)
    decision = auth.disable_account(user_id)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.post("/admin/accounts/{user_id}/enable")
def admin_enable(user_id: str, x_auth_token: Optional[str] = Header(default=None)):
    """管理员重新启用账号（旧会话不复活，需重新登录）。"""
    _require_admin(x_auth_token)
    decision = auth.enable_account(user_id)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.post("/account/password")
def change_password(body: PasswordBody, x_auth_token: Optional[str] = Header(default=None)):
    """修改本人口令：需要当前会话的 CSRF，成功后本账号既有会话立即失效。"""
    session, token = _require_session(x_auth_token)
    if body.csrf_token != session.csrf_token:
        raise _deny_http(DenialReason.CSRF_MISMATCH, "保护信息不匹配")
    decision = auth.change_account_password(session.user_id, body.new_password)
    if not decision.allowed:
        raise _deny_http(decision.reason, decision.detail)
    return {"allowed": True, "detail": decision.detail}


@app.get("/resource/{resource_id}")
def read_resource(resource_id: str, x_auth_token: Optional[str] = Header(default=None)):
    session, _ = _require_session(x_auth_token)
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
    session, _ = _require_session(x_auth_token)
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
