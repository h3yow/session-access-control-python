"""HTTP 层端到端：登录/刷新/重放/越权/保护校验，拒绝原因在响应中可区分。"""
import logging

from fastapi.testclient import TestClient

from main import app

log = logging.getLogger("verify.api")
client = TestClient(app)


def login(user_id: str, role: str) -> dict:
    r = client.post("/login", json={"user_id": user_id, "role": role})
    assert r.status_code == 200
    return r.json()


def test_http_refresh_and_old_token_replay():
    sess = login("alice", "owner")
    r = client.post("/refresh", headers={"x-auth-token": sess["token"]})
    assert r.status_code == 200
    replay = client.get("/resource/r-alice", headers={"x-auth-token": sess["token"]})
    body = replay.json()["detail"]
    log.info("request=read(token=rotated) status=%s reason=%s detail=%s",
             replay.status_code, body["reason"], body["detail"])
    assert replay.status_code == 401 and body["reason"] == "token_rotated"


def test_http_expired_and_revoked_distinguishable(monkeypatch):
    from main import auth as service
    # 通过刷新后手工将过期时间回拨，构造过期响应。
    sess = login("alice", "owner")
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
    viewer = login("carol", "viewer")
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

    owner_b = login("bob", "owner")
    r = client.get("/resource/r-alice", headers={"x-auth-token": owner_b["token"]})
    body = r.json()["detail"]
    log.info("request=other-owner->private reason=%s detail=%s", body["reason"], body["detail"])
    assert body["reason"] == "not_owner"


def test_http_protected_write_csrf():
    sess = login("alice", "owner")
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
