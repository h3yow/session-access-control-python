"""HTTP 层端到端：本地账号登录/刷新/重放/越权/保护校验/合法写回读，
拒绝原因在响应中可区分。"""
import logging

import pytest
from fastapi.testclient import TestClient

import main as main_module
from main import app
from app.auth import AuthService
from app.models import Resource

log = logging.getLogger("verify.api")


@pytest.fixture(autouse=True)
def fresh_service():
    """每个用例重建全局 AuthService 与本地资源，避免限流计数、账号状态、
    资源内容跨用例污染（模块级单例无法随 pytest fixture 自动隔离）。"""
    main_module.auth = AuthService(ttl_seconds=300.0)
    main_module._resources.clear()
    main_module._resources.update(
        {
            "r-public": Resource("r-public", owner_id="alice", visibility="public", content="公开资料"),
            "r-alice": Resource("r-alice", owner_id="alice", visibility="private", content="Alice 私有"),
            "r-bob": Resource("r-bob", owner_id="bob", visibility="private", content="Bob 私有"),
        }
    )
    yield


client = TestClient(app)

# 与 main.py / AuthService 默认本地账号一致的演示口令（非真实生产凭据）。
PASSWORDS = {"root": "root-pw", "alice": "alice-pw", "bob": "bob-pw",
             "carol": "carol-pw", "dave": "dave-pw"}


def login(user_id: str) -> dict:
    r = client.post("/login", json={"user_id": user_id, "password": PASSWORDS[user_id]})
    assert r.status_code == 200, r.text
    sess = r.json()
    log.info("request=login(user=%s) role=%s allowed=True", user_id, sess["role"])
    return sess


def _reason(r) -> str:
    return r.json()["detail"]["reason"]


def test_http_login_failures_distinguishable():
    cases = [
        ("ghost", "x", "account_not_found"),
        ("dave", "dave-pw", "account_disabled"),
        ("alice", "wrong-pw", "bad_password"),
    ]
    for user, pw, expected in cases:
        r = client.post("/login", json={"user_id": user, "password": pw})
        log.info("request=login(user=%s) status=%s reason=%s detail=%s",
                 user, r.status_code, _reason(r), r.json()["detail"]["detail"])
        assert r.status_code == 401 and _reason(r) == expected


def test_http_role_taken_from_account_not_request():
    # 请求中没有 role 字段；viewer 账号登录后拿到的角色只能是 viewer。
    sess = login("carol")
    assert sess["role"] == "viewer"


def test_http_refresh_and_old_token_replay():
    sess = login("alice")
    r = client.post("/refresh", headers={"x-auth-token": sess["token"]})
    assert r.status_code == 200
    replay = client.get("/resource/r-alice", headers={"x-auth-token": sess["token"]})
    body = replay.json()["detail"]
    log.info("request=read(token=rotated) status=%s reason=%s detail=%s",
             replay.status_code, body["reason"], body["detail"])
    assert replay.status_code == 401 and body["reason"] == "token_rotated"


def test_http_expired_and_revoked_distinguishable(monkeypatch):
    from main import auth as service
    sess = login("alice")
    sid, token = sess["session_id"], sess["token"]
    service._sessions[sid].expires_at = 0  # type: ignore[attr-defined]
    r = client.get("/resource/r-alice", headers={"x-auth-token": token})
    body = r.json()["detail"]
    log.info("request=read(expired) reason=%s", body["reason"])
    assert body["reason"] == "session_expired"
    client.post(f"/revoke/{sid}")
    r2 = client.post("/refresh", headers={"x-auth-token": token})
    log.info("request=refresh(revoked) reason=%s", r2.json()["detail"]["reason"])
    assert r2.json()["detail"]["reason"] == "session_revoked"


def test_http_privilege_escalation_denied():
    viewer = login("carol")
    r = client.get("/resource/r-alice", headers={"x-auth-token": viewer["token"]})
    body = r.json()["detail"]
    log.info("request=viewer->private reason=%s detail=%s", body["reason"], body["detail"])
    assert r.status_code == 403 and body["reason"] == "forbidden_role"

    r = client.put(
        "/resource/r-public",
        headers={"x-auth-token": viewer["token"]},
        json={"content": "hack", "csrf_token": viewer["csrf_token"]},
    )
    body = r.json()["detail"]
    log.info("request=viewer->write reason=%s", body["reason"])
    assert body["reason"] == "forbidden_role"

    owner_b = login("bob")
    r = client.get("/resource/r-alice", headers={"x-auth-token": owner_b["token"]})
    body = r.json()["detail"]
    log.info("request=other-owner->private reason=%s detail=%s", body["reason"], body["detail"])
    assert body["reason"] == "not_owner"


def test_http_authorized_write_takes_effect_and_reads_back():
    """正向分支：owner 写自有资源必须成功，随后读取能看到新内容。"""
    sess = login("alice")
    new_content = f"Alice 更新于本测试 {sess['session_id'][:8]}"
    r = client.put(
        "/resource/r-alice",
        headers={"x-auth-token": sess["token"]},
        json={"content": new_content, "csrf_token": sess["csrf_token"]},
    )
    log.info("request=owner->write-own status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 200 and r.json()["content"] == new_content

    r2 = client.get("/resource/r-alice", headers={"x-auth-token": sess["token"]})
    log.info("request=read-after-write content=%r", r2.json()["content"])
    assert r2.status_code == 200 and r2.json()["content"] == new_content

    # 管理员写他人私有资源同样生效。
    admin = login("root")
    r3 = client.put(
        "/resource/r-bob",
        headers={"x-auth-token": admin["token"]},
        json={"content": "admin 代更新", "csrf_token": admin["csrf_token"]},
    )
    assert r3.status_code == 200 and r3.json()["content"] == "admin 代更新"


def test_http_protected_write_csrf():
    sess = login("alice")
    r = client.post(
        "/session/note",
        headers={"x-auth-token": sess["token"]},
        json={"note": "n", "csrf_token": "bad"},
    )
    body = r.json()["detail"]
    log.info("request=note(csrf=bad) reason=%s", body["reason"])
    assert r.status_code == 403 and body["reason"] == "csrf_mismatch"

    r = client.post(
        "/session/note",
        headers={"x-auth-token": sess["token"]},
        json={"note": "n", "csrf_token": sess["csrf_token"], "expected_version": 5},
    )
    body = r.json()["detail"]
    log.info("request=note(version=stale) reason=%s detail=%s", body["reason"], body["detail"])
    assert r.status_code == 409 and body["reason"] == "version_conflict"

    # 正向：CSRF 正确且不带过期版本时写入生效，version 递增。
    r = client.post(
        "/session/note",
        headers={"x-auth-token": sess["token"]},
        json={"note": "hello", "csrf_token": sess["csrf_token"]},
    )
    log.info("request=note(valid) body=%s", r.json())
    assert r.status_code == 200 and r.json()["note"] == "hello" and r.json()["version"] == 1


def test_http_disable_account_invalidates_sessions():
    admin = login("root")
    sess = login("bob")
    r = client.post("/admin/accounts/bob/disable", headers={"x-auth-token": admin["token"]})
    assert r.status_code == 200, r.text
    r2 = client.get("/resource/r-bob", headers={"x-auth-token": sess["token"]})
    log.info("request=read(after disable) reason=%s", _reason(r2))
    assert _reason(r2) == "account_state_changed"
    r3 = client.post("/login", json={"user_id": "bob", "password": "bob-pw"})
    assert _reason(r3) == "account_disabled"

    # 非管理员不能停用账号。
    alice = login("alice")
    r4 = client.post("/admin/accounts/alice/disable", headers={"x-auth-token": alice["token"]})
    log.info("request=non-admin disable reason=%s", _reason(r4))
    assert _reason(r4) == "forbidden_role"

    client.post("/admin/accounts/bob/enable", headers={"x-auth-token": admin["token"]})


def test_http_change_own_password_invalidates_old_session():
    sess = login("alice")
    r = client.post(
        "/account/password",
        headers={"x-auth-token": sess["token"]},
        json={"new_password": "alice-pw2", "csrf_token": sess["csrf_token"]},
    )
    assert r.status_code == 200, r.text
    r2 = client.get("/resource/r-alice", headers={"x-auth-token": sess["token"]})
    log.info("request=read(after password change) reason=%s", _reason(r2))
    assert _reason(r2) == "account_state_changed"
    bad = client.post("/login", json={"user_id": "alice", "password": "alice-pw"})
    assert _reason(bad) == "bad_password"
    ok = client.post("/login", json={"user_id": "alice", "password": "alice-pw2"})
    assert ok.status_code == 200
    # 还原口令，避免影响同进程内其他用例。
    client.post(
        "/account/password",
        headers={"x-auth-token": ok.json()["token"]},
        json={"new_password": "alice-pw", "csrf_token": ok.json()["csrf_token"]},
    )
