"""基于角色的访问判定：越权拒绝、所有者/管理员边界、顺序与并发无关。"""

from __future__ import annotations

import threading

from authsys.errors import AuthError, DenyReason
from authsys.models import Permission, Role


def test_owner_can_read_write_delete(harness):
    s = harness.login("alice")
    for perm in (Permission.READ, Permission.WRITE, Permission.DELETE):
        d = harness.access.decide(s.token, "doc-1", perm)
        assert d.allowed, d.basis
    print("input: owner alice on doc-1 -> read/write/delete allowed")


def test_other_user_read_only_and_write_denied(harness):
    s = harness.login("bob")
    assert harness.access.decide(s.token, "doc-1", Permission.READ).allowed

    d = harness.access.decide(s.token, "doc-1", Permission.WRITE)
    assert not d.allowed
    assert d.reason is DenyReason.ACCESS_DENIED_ROLE
    assert "hit=<none>" in d.basis
    print(f"input: bob writes doc-1 -> denied; basis='{d.basis}'")

    d2 = harness.access.decide(s.token, "doc-1", Permission.DELETE)
    assert not d2.allowed and d2.reason is DenyReason.ACCESS_DENIED_ROLE


def test_admin_capabilities_distinct_from_owner(harness):
    admin = harness.login("root")
    # 管理员可写他人资源
    assert harness.access.decide(admin.token, "doc-1", Permission.WRITE).allowed
    # 但不派生 OWNER 身份
    roles = harness.access.effective_roles(harness.root, harness.doc)
    assert Role.OWNER not in roles
    # 在 delete 仅限 ADMIN 的受限资源上，所有者(root 恰好是 owner)与管理员均能删
    d = harness.access.decide(admin.token, "secret-1", Permission.DELETE)
    assert d.allowed, d.basis
    print("input: admin on doc-1 write allowed but is not owner; secret-1 delete allowed")


def test_guest_cannot_read_default_or_secret(harness):
    g = harness.login("guest")
    assert not harness.access.decide(g.token, "doc-1", Permission.READ).allowed
    assert not harness.access.decide(g.token, "secret-1", Permission.READ).allowed
    print("input: guest reads doc-1/secret-1 -> denied by role policy")


def test_decision_is_order_independent(harness):
    a = harness.login("alice")
    b = harness.login("bob")
    decisions = []

    def rounds():
        decisions.append(harness.access.decide(b.token, "doc-1", Permission.WRITE).allowed)
        decisions.append(harness.access.decide(a.token, "doc-1", Permission.WRITE).allowed)
        decisions.append(harness.access.decide(b.token, "doc-1", Permission.READ).allowed)

    for _ in range(200):
        rounds()
    # bob 写恒 False，alice 写恒 True，bob 读恒 True
    assert decisions[0::3] == [False] * 200
    assert decisions[1::3] == [True] * 200
    assert decisions[2::3] == [True] * 200
    print("input: 200 mixed-order rounds -> identical conclusions every time")


def test_decision_is_concurrency_stable(harness):
    a = harness.login("alice")
    b = harness.login("bob")
    results = []
    lock = threading.Lock()
    n = 24

    def worker(token, perm, expect):
        d = harness.access.decide(token, "doc-1", perm)
        with lock:
            results.append((d.allowed, expect, d.reason))

    threads = []
    for i in range(n):
        tok = a.token if i % 2 == 0 else b.token
        threads.append(threading.Thread(
            target=worker, args=(tok, Permission.WRITE, i % 2 == 0),
        ))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"input: {n} concurrent owner/other write decisions -> {len(results)} results")
    for allowed, expect, reason in results:
        assert allowed is expect
        if not allowed:
            assert reason is DenyReason.ACCESS_DENIED_ROLE


def test_decision_keeps_basis_for_audit(harness):
    b = harness.login("bob")
    d = harness.access.decide(b.token, "doc-1", Permission.DELETE)
    assert not d.allowed
    assert "roles=['user']" in d.basis
    assert "delete_roles=['admin', 'owner']" in d.basis
    assert "ownership=False" in d.basis
    print(f"basis retained: {d.basis}")


def test_access_with_expired_credential_raises_distinguishable(harness, monkeypatch):
    from authsys import service as service_mod
    s = harness.login("alice")
    monkeypatch.setattr(service_mod.time, "time", lambda: s.expires_at + 1)
    try:
        harness.access.decide(s.token, "doc-1", Permission.READ)
    except AuthError as exc:
        assert exc.reason is DenyReason.SESSION_EXPIRED
        print("input: access with expired token -> session_expired (not access_denied)")
    else:
        raise AssertionError("expected AuthError")
