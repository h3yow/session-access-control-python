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


def test_http_admin_account_actions_require_admin_session():
    """停用/改口令是管理操作：未登录 401，已登录但非管理员 403 admin_required，管理员 200。"""
    # 1) 完全不带凭据：与"权限不够"明确区分，报会话级原因
    r = client.post("/accounts/bob/disable")
    body = r.json()["detail"]
    log.info("request=disable(no credential) status=%s reason=%s", r.status_code, body["reason"])
    assert r.status_code == 401 and body["reason"] == "session_not_found"

    r = client.post(
        "/accounts/bob/password",
        json={"new_password": "stolen-pw"},
    )
    body = r.json()["detail"]
    log.info("request=change_password(no credential) status=%s reason=%s", r.status_code, body["reason"])
    assert r.status_code == 401 and body["reason"] == "session_not_found"

    # 2) owner/viewer 已登录但无权：明确拒绝为 admin_required，且操作未生效
    owner = login("alice")
    r = client.post("/accounts/bob/disable", headers={"x-auth-token": owner["token"]})
    body = r.json()["detail"]
    log.info("request=disable(by owner) status=%s reason=%s detail=%s",
             r.status_code, body["reason"], body["detail"])
    assert r.status_code == 403 and body["reason"] == "admin_required"

    viewer = login("carol")
    r = client.post(
        "/accounts/bob/password",
        headers={"x-auth-token": viewer["token"]},
        json={"new_password": "stolen-pw"},
    )
    body = r.json()["detail"]
    log.info("request=change_password(by viewer) status=%s reason=%s", r.status_code, body["reason"])
    assert r.status_code == 403 and body["reason"] == "admin_required"

    # 越权改密未生效：旧口令仍可登录，攻击者指定的口令登录失败
    assert login("bob")  # 旧口令仍有效
    r = client.post("/login", json={"username": "bob", "password": "stolen-pw"})
    log.info("request=login(bob, stolen pw after denied change) status=%s", r.status_code)
    assert r.status_code == 401

    # 3) 管理员可以执行：停用后目标账号旧会话立即失效；改密后新口令可登录
    root = login("root")
    r = client.post("/accounts/bob/disable", headers={"x-auth-token": root["token"]})
    log.info("request=disable(by admin) status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 200

    # 恢复 bob，避免影响其他用例
    from main import accounts as store
    store.set_enabled("bob", True)

    r = client.post(
        "/accounts/bob/password",
        headers={"x-auth-token": root["token"]},
        json={"new_password": "bob-new-pw"},
    )
    log.info("request=change_password(by admin) status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 200
    r = client.post("/login", json={"username": "bob", "password": "bob-new-pw"})
    log.info("request=login(bob, admin-set new pw) status=%s", r.status_code)
    assert r.status_code == 200
    r = client.post("/login", json={"username": "bob", "password": "bob-pw"})
    assert r.status_code == 401 and r.json()["detail"]["reason"] == "password_mismatch"
    # 还原 bob 口令，避免污染同进程内其他用例
    store.change_password("bob", "bob-pw")


def test_http_account_disable_invalidates_session():
    root = login("root")
    sess = login("bob")
    r = client.post("/accounts/bob/disable", headers={"x-auth-token": root["token"]})
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


def test_http_disable_atomic_against_concurrent_refresh():
    """HTTP 路径：admin 停用与目标账号并发续期竞争，停用完成后无可用凭据。"""
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from main import auth as service, accounts as store

    sess = login("carol")
    token = sess["token"]
    root = login("root")
    n = 12
    barrier = threading.Barrier(n + 1)
    refreshed = []

    def carol_refresh(i):
        barrier.wait()
        r = client.post("/refresh", headers={"x-auth-token": token})
        log.info("request=refresh#%d status=%s", i, r.status_code)
        if r.status_code == 200:
            refreshed.append(r.json()["token"])
        else:
            assert r.json()["detail"]["reason"] in (
                "token_rotated", "session_invalidated")

    def admin_disable():
        barrier.wait()
        r = client.post("/accounts/carol/disable", headers={"x-auth-token": root["token"]})
        log.info("request=disable(carol by root) status=%s", r.status_code)
        assert r.status_code == 200

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futs = [pool.submit(carol_refresh, i) for i in range(n)]
        futs.append(pool.submit(admin_disable))
        for f in futs:
            f.result()

    # 停用完成后：原凭据与竞争中续期出的新凭据一律 session_invalidated
    for t in [token] + refreshed:
        r = client.get("/resource/r-public", headers={"x-auth-token": t})
        body = r.json()["detail"]
        log.info("request=read after disable storm reason=%s", body["reason"])
        assert r.status_code == 401 and body["reason"] == "session_invalidated"
    assert not service.get_active_session(token)
    # carol 旧口令也无法再登录
    r = client.post("/login", json={"username": "carol", "password": "carol-pw"})
    assert r.status_code == 401 and r.json()["detail"]["reason"] == "account_disabled"
    # 恢复
    store.set_enabled("carol", True)
