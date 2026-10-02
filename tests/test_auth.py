"""会话生命周期：本地账号登录、校验、过期、轮换、撤销，拒绝原因必须可区分。"""
import logging

from app.models import DenialReason

log = logging.getLogger("verify.auth")


def login_ok(auth, user_id: str, password: str = ""):
    """测试辅助：本地账号登录并断言成功，返回会话。"""
    password = password or f"{user_id}-pw"
    d, session = auth.login(user_id, password)
    log.info("request=login(user=%s) allowed=%s reason=%s", user_id, d.allowed, d.reason)
    assert d.allowed, d.detail
    return session


def test_login_and_validate(auth):
    s = login_ok(auth, "alice")
    d = auth.validate(s.token)
    log.info("request=validate(token=%s...) decision=%s detail=%s", s.token[:8], d.allowed, d.detail)
    assert d.allowed


def test_login_unknown_token(auth):
    d = auth.validate("never-issued")
    log.info("request=validate(unknown) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.SESSION_NOT_FOUND


def test_expired_token(auth, clock):
    s = login_ok(auth, "alice")
    clock.advance(61.0)
    d = auth.validate(s.token)
    log.info("request=validate(expired) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.SESSION_EXPIRED


def test_refresh_rotates_and_old_token_distinguishable(auth):
    s = login_ok(auth, "alice")
    old_token = s.token
    d, new_session = auth.refresh(old_token)
    log.info("request=refresh(old) decision=%s new_version=%s", d.allowed, new_session.version)
    assert d.allowed and new_session.token != old_token

    d_old = auth.validate(old_token)
    log.info("request=validate(rotated old) reason=%s", d_old.reason)
    assert not d_old.allowed and d_old.reason is DenialReason.TOKEN_ROTATED

    d_new = auth.validate(new_session.token)
    assert d_new.allowed


def test_refresh_extends_lifetime(auth, clock):
    s = login_ok(auth, "alice")
    clock.advance(50.0)
    d, ns = auth.refresh(s.token)
    assert d.allowed
    clock.advance(50.0)  # 距登录 100s，绝对上限 200s，未到；新凭据仍有效
    d_new = auth.validate(ns.token)
    log.info("request=validate(after refresh, t=100/200) decision=%s", d_new.allowed)
    assert d_new.allowed


def test_revoked_session_distinguishable(auth):
    s = login_ok(auth, "alice")
    auth.revoke(s.session_id)
    d = auth.validate(s.token)
    log.info("request=validate(revoked) reason=%s", d.reason)
    assert not d.allowed and d.reason is DenialReason.SESSION_REVOKED


def test_revoke_unknown_session(auth):
    d = auth.revoke("no-such-session")
    log.info("request=revoke(unknown) reason=%s", d.reason)
    assert not d.allowed and d.reason is DenialReason.SESSION_NOT_FOUND


def test_refresh_of_revoked_session(auth):
    s = login_ok(auth, "alice")
    auth.revoke(s.session_id)
    d, ns = auth.refresh(s.token)
    log.info("request=refresh(revoked) reason=%s", d.reason)
    assert not d.allowed and d.reason is DenialReason.SESSION_REVOKED and ns is None
