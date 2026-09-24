"""会话生命周期：登录、有效期、刷新延长、过期/轮换/撤销三态可区分。"""

from __future__ import annotations

import pytest

from authsys import service as service_mod
from authsys.errors import AuthError, DenyReason


def test_login_success_and_protected_access(harness):
    s = harness.login("alice")
    print(f"input: login alice/pw123 -> token={s.token[:8]}... version={s.version}")

    live = harness.service.authenticate(s.token)
    assert live.session_id == s.session_id
    print("basis: token indexed and within sliding/absolute ttl -> allowed")


def test_login_wrong_password_is_rejected(harness):
    with pytest.raises(AuthError) as exc:
        harness.login("alice", "wrong-password")
    assert exc.value.reason is DenyReason.INVALID_CREDENTIALS
    print(f"input: bad password -> reason={exc.value.reason.value}")


def test_expired_session_is_distinguishable(harness, monkeypatch):
    s = harness.login("alice")
    fake_now = s.expires_at + 1  # 滑动过期之后、绝对过期之前
    monkeypatch.setattr(service_mod.time, "time", lambda: fake_now)
    with pytest.raises(AuthError) as exc:
        harness.service.authenticate(s.token)
    assert exc.value.reason is DenyReason.SESSION_EXPIRED
    print(f"input: token at t={fake_now} -> reason={exc.value.reason.value} (sliding)")


def test_absolute_expiry_blocks_refresh(harness, monkeypatch):
    """刷新不能突破绝对有效期；绝对过期后只能得到 SESSION_EXPIRED。"""
    s = harness.login("alice")
    fake_now = s.absolute_expires_at + 1
    monkeypatch.setattr(service_mod.time, "time", lambda: fake_now)
    with pytest.raises(AuthError) as exc:
        harness.service.refresh(s.token)
    assert exc.value.reason is DenyReason.SESSION_EXPIRED
    print(f"input: refresh at t={fake_now} -> reason={exc.value.reason.value} (absolute)")


def test_refresh_extends_sliding_ttl_within_absolute(harness):
    s = harness.login("alice")
    old_expires = s.expires_at
    r = harness.service.refresh(s.token)
    new_session = harness.service.authenticate(r.new_token)
    assert new_session.expires_at > old_expires
    assert new_session.expires_at <= s.absolute_expires_at
    print(
        f"input: refresh token={s.token[:8]}... "
        f"basis: expires {old_expires:.0f} -> {new_session.expires_at:.0f} "
        f"<= absolute {s.absolute_expires_at:.0f}",
    )


def test_old_token_after_refresh_is_rotated(harness):
    s = harness.login("alice")
    harness.service.refresh(s.token)
    with pytest.raises(AuthError) as exc:
        harness.service.authenticate(s.token)
    assert exc.value.reason is DenyReason.SESSION_ROTATED
    print("input: replay old token -> reason=session_rotated")


def test_revoked_token_is_distinguishable(harness):
    s = harness.login("alice")
    harness.service.logout(s.token)
    with pytest.raises(AuthError) as exc:
        harness.service.authenticate(s.token)
    assert exc.value.reason is DenyReason.SESSION_REVOKED
    print("input: use revoked token -> reason=session_revoked")


def test_unknown_token_is_not_found(harness):
    with pytest.raises(AuthError) as exc:
        harness.service.authenticate("never-issued-token")
    assert exc.value.reason is DenyReason.SESSION_NOT_FOUND
    print("input: unknown token -> reason=session_not_found")


@pytest.mark.parametrize("play_again", [1, 2, 5])
def test_dead_credential_conclusion_is_stable(harness, play_again):
    """旧凭据无论重放多少次，结论恒定为 SESSION_ROTATED。"""
    s = harness.login("alice")
    harness.service.refresh(s.token)
    reasons = []
    for _ in range(play_again):
        try:
            harness.service.authenticate(s.token)
        except AuthError as exc:
            reasons.append(exc.reason)
    assert reasons == [DenyReason.SESSION_ROTATED] * play_again
    print(f"input: replay x{play_again} -> all session_rotated")


def test_admin_revoke_is_distinguishable(harness):
    s = harness.login("alice")
    assert harness.service.revoke_session(s.session_id) is True
    with pytest.raises(AuthError) as exc:
        harness.service.authenticate(s.token)
    assert exc.value.reason is DenyReason.SESSION_REVOKED
    # 重复吊销不产生状态变更
    assert harness.service.revoke_session(s.session_id) is False
    print("input: admin revoke by session_id -> session_revoked; idempotent")


def test_proof_after_revoke_is_rejected(harness):
    s = harness.login("alice")
    proof = s.proof
    harness.service.logout(s.token)
    with pytest.raises(AuthError) as exc:
        harness.service.protected_write(s.token, proof, 1, lambda x: None)
    assert exc.value.reason is DenyReason.SESSION_REVOKED
    print("input: write with revoked token -> session_revoked before proof checks")
