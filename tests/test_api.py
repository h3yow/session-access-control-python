"""HTTP 层端到端：登录/刷新/重放/越权/保护校验，拒绝原因在响应中可区分。"""
import logging

from fastapi.testclient import TestClient

from main import app

log = logging.getLogger("verify.api")
client = TestClient(app)


def login(username: str, password: str = None) -> dict:
    r = client.post("/login", json={"username": username, "password": password or f"{username}-pw"})
    assert r.status_code == 200
    return r.json()


def test_http_login_failures_distinguishable():
    r = client.post("/login", json={"username": "nobody", "password": "x"})
    body = r.json()["detail"]
    log.info("request=login(unknown user) status=%s reason=%s", r.status_code, body["reason"])
    assert r.status_code == 401 and body["reason"] == "account_unknown"

    r = client.post("/login", json={"username": "alice", "password": "wrong"})
    body = r.json()["detail"]
    log.info("request=login(wrong password) reason=%s", body["reason"])
    assert r.status_code == 401 and body["reason"] == "password_mismatch"

    r = client.post("/login", json={"username": "dave", "password": "dave-pw"})
    body = r.json()["detail"]
    log.info("request=login(disabled, correct password) reason=%s", body["reason"])
    assert r.status_code == 401 and body["reason"] == "account_disabled"


def test_http_refresh_and_old_token_replay():
    sess = login("alice")
    r = client.post("/refresh", headers={"x-auth-token": sess["token"]})
    assert r.status_code == 200
    replay = client.get("/resource/r-alice", headers={"x-auth-token": sess["token"]})
    body = replay.json()["detail"]
    log.info("request=read(token=rotated) status=%s reason=%s detail=%s",
             replay.status_code, body["reason"], body["detail"])
    assert replay.status_code == 401 and body["reason"] == "token_rotated"


def test_http_expired_and_revoked_distinguishable():
    from main import auth as service
    # 通过刷新后手工将过期时间回拨，构造过期响应。
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


def test_http_authorized_write_takes_effect_and_is_readable():
    """有权限的合法写入必须成功生效，后续读取能看到新内容。"""
    sess = login("alice")
    r = client.put(
        "/resource/r-alice",
        headers={"x-auth-token": sess["token"]},
        json={"content": "Alice 更新后的内容", "csrf_token": sess["csrf_token"]},
    )
    log.info("request=owner->write own private status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 200 and r.json()["allowed"]

    r2 = client.get("/resource/r-alice", headers={"x-auth-token": sess["token"]})
    log.info("request=read after write content=%r", r2.json()["content"])
    assert r2.status_code == 200 and r2.json()["content"] == "Alice 更新后的内容"


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


def test_http_account_disable_invalidates_session():
    admin = login("root")
    sess = login("bob")
    r = client.post("/accounts/bob/disable", headers={"x-auth-token": admin["token"]})
    assert r.status_code == 200
    r2 = client.get("/resource/r-bob", headers={"x-auth-token": sess["token"]})
    body = r2.json()["detail"]
    log.info("request=read(after disable) reason=%s detail=%s", body["reason"], body["detail"])
    assert r2.status_code == 401 and body["reason"] == "session_invalidated"
    r3 = client.post("/refresh", headers={"x-auth-token": sess["token"]})
    log.info("request=refresh(after disable) reason=%s", r3.json()["detail"]["reason"])
    assert r3.json()["detail"]["reason"] == "session_invalidated"
    # 恢复，避免影响其他用例
    from main import accounts as store
    store.set_enabled("bob", True)


def test_http_account_management_requires_login():
    """未登录调用停用/改口令：401 session_not_found，与权限不足可区分。"""
    for desc, r in (
        ("disable", client.post("/accounts/alice/disable")),
        ("password", client.post("/accounts/alice/password", json={"new_password": "x"})),
    ):
        body = r.json()["detail"]
        log.info("request=%s(no token) status=%s reason=%s", desc, r.status_code, body["reason"])
        assert r.status_code == 401 and body["reason"] == "session_not_found"


def test_http_account_management_requires_admin_role():
    """已登录但非 admin：403 forbidden_role；且操作不得生效。"""
    for who in ("alice", "carol"):  # owner / viewer 都不够权限
        sess = login(who)
        r = client.post("/accounts/bob/disable", headers={"x-auth-token": sess["token"]})
        body = r.json()["detail"]
        log.info("request=disable(by %s) status=%s reason=%s detail=%s",
                 who, r.status_code, body["reason"], body["detail"])
        assert r.status_code == 403 and body["reason"] == "forbidden_role"
        r = client.post(
            "/accounts/bob/password",
            headers={"x-auth-token": sess["token"]},
            json={"new_password": "hijacked"},
        )
        body = r.json()["detail"]
        log.info("request=change_password(by %s) status=%s reason=%s", who, r.status_code, body["reason"])
        assert r.status_code == 403 and body["reason"] == "forbidden_role"
    # 越权尝试不得产生任何效果：bob 未被停用、口令未被改
    r = client.post("/login", json={"username": "bob", "password": "bob-pw"})
    log.info("request=login(bob after blocked attempts) status=%s", r.status_code)
    assert r.status_code == 200


def test_http_admin_change_password_takes_effect():
    """admin 改口令：操作生效，旧口令不能再登录，新口令可以，旧会话失效。"""
    admin = login("root")
    sess = login("bob")
    r = client.post(
        "/accounts/bob/password",
        headers={"x-auth-token": admin["token"]},
        json={"new_password": "bob-new-pw"},
    )
    log.info("request=admin change_password(bob) status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 200 and r.json()["allowed"]

    r = client.get("/resource/r-bob", headers={"x-auth-token": sess["token"]})
    log.info("request=read(old session after password change) reason=%s", r.json()["detail"]["reason"])
    assert r.json()["detail"]["reason"] == "session_invalidated"

    r = client.post("/login", json={"username": "bob", "password": "bob-pw"})
    log.info("request=login(old password) reason=%s", r.json()["detail"]["reason"])
    assert r.status_code == 401 and r.json()["detail"]["reason"] == "password_mismatch"

    r = client.post("/login", json={"username": "bob", "password": "bob-new-pw"})
    log.info("request=login(new password) status=%s", r.status_code)
    assert r.status_code == 200

    # 恢复口令，避免影响其他用例
    r = client.post(
        "/accounts/bob/password",
        headers={"x-auth-token": admin["token"]},
        json={"new_password": "bob-pw"},
    )
    assert r.status_code == 200
