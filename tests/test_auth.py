"""会话生命周期：登录、校验、过期、轮换、撤销，拒绝原因必须可区分。"""
import logging

from app.models import DenialReason
from tests.conftest import do_login

log = logging.getLogger("verify.auth")


def test_login_and_validate(auth):
    s = do_login(auth, "alice")
    d = auth.validate(s.token)
    log.info("request=validate(token=%s...) decision=%s detail=%s", s.token[:8], d.allowed, d.detail)
    assert d.allowed


def test_login_role_comes_from_account(auth):
    """会话角色以账号为准，调用方无法指定。"""
    s = do_login(auth, "carol")
    log.info("request=login(carol) role=%s", s.role.value)
    assert s.role.value == "viewer"


def test_unknown_token(auth):
    d = auth.validate("never-issued")
    log.info("request=validate(unknown) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.SESSION_NOT_FOUND


def test_expired_token(auth, clock):
    s = do_login(auth, "alice")
    clock.advance(61.0)
    d = auth.validate(s.token)
    log.info("request=validate(expired) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.SESSION_EXPIRED


def test_refresh_rotates_and_old_token_distinguishable(auth):
    s = do_login(auth, "alice")
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
    s = do_login(auth, "alice")
    clock.advance(50.0)
    d, ns = auth.refresh(s.token)
    assert d.allowed
    clock.advance(50.0)  # 原凭据此刻已过期，新凭据仍有效
    d_new = auth.validate(ns.token)
    log.info("request=validate(after refresh, t=100) decision=%s", d_new.allowed)
    assert d_new.allowed


def test_revoked_session_distinguishable(auth):
    s = do_login(auth, "alice")
    auth.revoke(s.session_id)
    d = auth.validate(s.token)
    log.info("request=validate(revoked) reason=%s", d.reason)
    assert not d.allowed and d.reason is DenialReason.SESSION_REVOKED


def test_revoke_unknown_session(auth):
    d = auth.revoke("no-such-session")
    log.info("request=revoke(unknown) reason=%s", d.reason)
    assert not d.allowed and d.reason is DenialReason.SESSION_NOT_FOUND


def test_refresh_of_revoked_session(auth):
    s = do_login(auth, "alice")
    auth.revoke(s.session_id)
    d, ns = auth.refresh(s.token)
    log.info("request=refresh(revoked) reason=%s", d.reason)
    assert not d.allowed and d.reason is DenialReason.SESSION_REVOKED and ns is None
