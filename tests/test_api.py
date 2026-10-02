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
    sess = login("bob")
    r = client.post("/accounts/bob/disable")
    assert r.status_code == 200
    r2 = client.get("/resource/r-bob", headers={"x-auth-token": sess["token"]})
    body = r2.json()["detail"]
    log.info("request=read(after disable) reason=%s detail=%s", body["reason"], body["detail"])
    assert r2.status_code == 401 and body["reason"] == "session_invalidated"
    r3 = client.post("/refresh", headers={"x-auth-token": sess["token"]})
    log.info("request=refresh(after disable) reason=%s", r3.json()["detail"]["reason"])
    assert r3.json()["detail"]["reason"] == "session_invalidated"
    # 恢复，避免影响其他用例
    client.post("/accounts/bob/disable")  # 幂等再次调用无副作用
    from main import accounts as store
    store.set_enabled("bob", True)
