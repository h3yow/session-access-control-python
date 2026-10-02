"""账号状态变化（停用/改密）联动既有会话失效：立即生效、原因可区分、并发不漏网。"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason
from tests.conftest import PASSWORDS, do_login

log = logging.getLogger("verify.invalidation")


def test_disable_invalidates_all_existing_sessions(auth, accounts):
    s1 = do_login(auth, "alice")
    s2 = do_login(auth, "alice")  # 同一账号的第二个会话
    other = do_login(auth, "bob")

    d = accounts.set_enabled("alice", False)
    log.info("request=disable(alice) detail=%s", d.detail)
    assert d.allowed

    for i, s in enumerate((s1, s2)):
        d = auth.validate(s.token)
        log.info("request=validate(alice session#%d after disable) reason=%s", i, d.reason)
        assert not d.allowed and d.reason is DenialReason.SESSION_INVALIDATED
        d, _ = auth.refresh(s.token)
        log.info("request=refresh(alice session#%d after disable) reason=%s", i, d.reason)
        assert not d.allowed and d.reason is DenialReason.SESSION_INVALIDATED

    d = auth.validate(other.token)  # 其他账号不受影响
    log.info("request=validate(bob after alice disabled) allowed=%s", d.allowed)
    assert d.allowed


def test_password_change_invalidates_existing_sessions(auth, accounts):
    s = do_login(auth, "alice")
    d = accounts.change_password("alice", "new-alice-pw")
    log.info("request=change_password(alice) detail=%s", d.detail)
    assert d.allowed

    d = auth.validate(s.token)
    log.info("request=validate(after password change) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_INVALIDATED
    d, _ = auth.refresh(s.token)
    log.info("request=refresh(after password change) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_INVALIDATED

    # 新口令可登录，旧口令不可
    d, _ = auth.login("alice", PASSWORDS["alice"])
    assert d.reason is DenialReason.PASSWORD_MISMATCH
    d, s_new = auth.login("alice", "new-alice-pw")
    assert d.allowed and auth.validate(s_new.token).allowed


def test_invalidated_distinguishable_from_revoked_and_expired(auth, accounts, clock):
    s_disabled = do_login(auth, "alice")
    s_revoked = do_login(auth, "bob")
    s_expired = do_login(auth, "carol")

    accounts.set_enabled("alice", False)
    auth.revoke(s_revoked.session_id)
    clock.advance(61.0)  # carol 会话自然过期

    reasons = {name: auth.validate(s.token).reason
               for name, s in (("disabled", s_disabled), ("revoked", s_revoked), ("expired", s_expired))}
    log.info("distinguish: %s", reasons)
    assert reasons["disabled"] is DenialReason.SESSION_INVALIDATED
    assert reasons["revoked"] is DenialReason.SESSION_REVOKED
    assert reasons["expired"] is DenialReason.SESSION_EXPIRED


def test_disable_wins_over_rotated_and_expired(auth, accounts, clock):
    """会话级状态优先：停用后即使凭据已轮换/已过期，也报账号失效。"""
    s = do_login(auth, "alice")
    old_token = s.token
    auth.refresh(old_token)  # old_token 已轮换
    clock.advance(61.0)      # 新凭据也已过期
    accounts.set_enabled("alice", False)

    d = auth.validate(old_token)
    log.info("request=validate(rotated+disabled) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_INVALIDATED
    d = auth.validate(s.token)
    log.info("request=validate(expired+disabled) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_INVALIDATED


def test_concurrent_disable_no_request_slips_through(auth, accounts):
    """停用与并发访问同时发生：停用完成后不允许任何旧凭据请求成功。"""
    s = do_login(auth, "alice")
    token = s.token
    n = 16
    barrier = threading.Barrier(n + 1)
    results = []

    def access(i):
        barrier.wait()
        d = auth.validate(token)
        log.info("request=validate#%d allowed=%s reason=%s", i, d.allowed, d.reason)
        results.append(d)

    def disable():
        barrier.wait()
        accounts.set_enabled("alice", False)
        log.info("request=disable(alice) done")

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futs = [pool.submit(access, i) for i in range(n)]
        futs.append(pool.submit(disable))
        for f in futs:
            f.result()

    # 每个请求要么在停用前成功，要么在停用后以 SESSION_INVALIDATED 失败；
    # 停用完成后不允许再有成功（串行化保证结论二选一且一致）
    for d in results:
        assert d.allowed or d.reason is DenialReason.SESSION_INVALIDATED
    after = auth.validate(token)
    log.info("request=validate(after storm) reason=%s", after.reason)
    assert after.reason is DenialReason.SESSION_INVALIDATED
    succeeded = sum(1 for d in results if d.allowed)
    log.info("concurrent disable: %d succeeded before switch, %d invalidated", succeeded, n - succeeded)


def test_concurrent_password_change_and_refresh_single_survivor(auth, accounts):
    """改密与并发续期竞争：改密完成后不存在任何可用凭据。"""
    s = do_login(auth, "alice")
    token = s.token
    n = 8
    barrier = threading.Barrier(n + 1)
    refreshed = []

    def do_refresh(i):
        barrier.wait()
        d, ns = auth.refresh(token)
        log.info("request=refresh#%d allowed=%s reason=%s", i, d.allowed, d.reason)
        if d.allowed:
            refreshed.append(ns.token)
        return d

    def change_pw():
        barrier.wait()
        accounts.change_password("alice", "rotated-pw")
        log.info("request=change_password(alice) done")

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futs = [pool.submit(do_refresh, i) for i in range(n)]
        futs.append(pool.submit(change_pw))
        for f in futs:
            f.result()

    # 无论竞争结果如何，改密完成后旧纪元凭据（含竞争中新签发的）全部失效
    for t in [token] + refreshed:
        d = auth.validate(t)
        assert not d.allowed and d.reason is DenialReason.SESSION_INVALIDATED
    log.info("after password change: all %d tokens invalidated", 1 + len(refreshed))
