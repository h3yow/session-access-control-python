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


def test_concurrent_login_and_disable_no_usable_session_survives(auth, accounts):
    """登录与停用同时发生：停用返回后，竞争中签发的任何会话都必须不可用。

    复现的漏网场景：认证通过后、签发会话前停用完成，旧实现会把新纪元
    盖进刚签发的会话，使停用成功的账号仍持有可用会话。修复后认证与签发
    与状态切换互斥，每个登录要么完整先于停用（会话随纪元递增失效），
    要么完整后于停用（认证直接拒绝）。
    """
    n = 16
    barrier = threading.Barrier(n + 1)
    issued, denied = [], []

    def do_login_race(i):
        barrier.wait()
        d, s = auth.login("alice", PASSWORDS["alice"])
        log.info("request=login#%d(alice) allowed=%s reason=%s", i, d.allowed, d.reason)
        (issued if d.allowed else denied).append((d, s))

    def disable():
        barrier.wait()
        d = accounts.set_enabled("alice", False)
        log.info("request=disable(alice) allowed=%s detail=%s", d.allowed, d.detail)

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futs = [pool.submit(do_login_race, i) for i in range(n)]
        futs.append(pool.submit(disable))
        for f in futs:
            f.result()

    try:
        # 停用完成后：竞争中签发的会话一个都不能用，且原因一致为账号失效
        for i, (d, s) in enumerate(issued):
            v = auth.validate(s.token)
            log.info("request=validate(raced session#%d) allowed=%s reason=%s", i, v.allowed, v.reason)
            assert not v.allowed and v.reason is DenialReason.SESSION_INVALIDATED
            r, _ = auth.refresh(s.token)
            assert not r.allowed and r.reason is DenialReason.SESSION_INVALIDATED
        # 被挡的登录结论也必须一致：只能是"账号已停用"
        for d, _ in denied:
            assert d.reason is DenialReason.ACCOUNT_DISABLED
        # 停用完成后的新登录同样被挡
        d, s = auth.login("alice", PASSWORDS["alice"])
        log.info("request=login(after disable) allowed=%s reason=%s", d.allowed, d.reason)
        assert not d.allowed and d.reason is DenialReason.ACCOUNT_DISABLED and s is None
        log.info("concurrent login+disable: %d issued all invalidated, %d denied as disabled",
                 len(issued), len(denied))
    finally:
        accounts.set_enabled("alice", True)  # 恢复，避免影响其他用例


def test_concurrent_old_password_login_and_password_change(auth, accounts):
    """旧口令并发登录与改密竞争：改密返回后，旧口令签发的会话全部不可用，
    旧口令之后也不能再登录成功。"""
    n = 16
    barrier = threading.Barrier(n + 1)
    issued, denied = [], []

    def do_login_old(i):
        barrier.wait()
        d, s = auth.login("alice", PASSWORDS["alice"])  # 旧口令
        log.info("request=login#%d(old password) allowed=%s reason=%s", i, d.allowed, d.reason)
        (issued if d.allowed else denied).append((d, s))

    def change_pw():
        barrier.wait()
        d = accounts.change_password("alice", "brand-new-pw")
        log.info("request=change_password(alice) allowed=%s detail=%s", d.allowed, d.detail)

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futs = [pool.submit(do_login_old, i) for i in range(n)]
        futs.append(pool.submit(change_pw))
        for f in futs:
            f.result()

    try:
        # 改密完成后：竞争中用旧口令签发的会话一个都不能用
        for i, (d, s) in enumerate(issued):
            v = auth.validate(s.token)
            log.info("request=validate(old-pw session#%d) allowed=%s reason=%s", i, v.allowed, v.reason)
            assert not v.allowed and v.reason is DenialReason.SESSION_INVALIDATED
        # 被挡的旧口令登录结论一致且可区分：口令已不匹配；
        # 连续失败触发限流后为 account_locked，二者都是明确的拒绝而非放行
        for d, _ in denied:
            assert d.reason in (DenialReason.PASSWORD_MISMATCH, DenialReason.ACCOUNT_LOCKED)
        log.info("concurrent old-pw login+change: %d issued all invalidated, %d denied (%s)",
                 len(issued), len(denied),
                 {r.value for r in (d.reason for d, _ in denied)})
    finally:
        accounts.change_password("alice", PASSWORDS["alice"])  # 恢复口令（同时清除限流）

    # 确定性地验证：改密完成后旧口令不能再登录，新口令可以且会话可用
    # （在未触发限流的 bob 上验证，避免上面风暴的锁定状态干扰结论）
    accounts.change_password("bob", "bob-new-pw")
    try:
        d, s = auth.login("bob", PASSWORDS["bob"])
        log.info("request=login(old password, after change) allowed=%s reason=%s", d.allowed, d.reason)
        assert not d.allowed and d.reason is DenialReason.PASSWORD_MISMATCH and s is None
        d, s = auth.login("bob", "bob-new-pw")
        log.info("request=login(new password) allowed=%s", d.allowed)
        assert d.allowed and auth.validate(s.token).allowed
    finally:
        accounts.change_password("bob", PASSWORDS["bob"])


def test_disable_landing_between_authenticate_and_issue(auth, accounts, monkeypatch):
    """确定性复现竞态窗口：停用恰好落在"认证通过"与"签发会话"之间。

    旧实现在此窗口内会把停用后的新纪元盖进刚签发的会话，留下可用会话；
    修复后即使状态切换插进该窗口，会话也以认证时刻的纪元签发，必然失效。
    """
    original = accounts.authenticate
    fired = []

    def authenticate_then_disable(username, password):
        decision, account = original(username, password)
        if decision.allowed and not fired:
            fired.append(True)
            d = accounts.set_enabled("alice", False)  # 模拟并发停用在此刻完成
            log.info("request=disable(alice, mid-login) detail=%s", d.detail)
        return decision, account

    monkeypatch.setattr(accounts, "authenticate", authenticate_then_disable)
    try:
        d, s = auth.login("alice", PASSWORDS["alice"])
        log.info("request=login(raced with disable) allowed=%s reason=%s", d.allowed, d.reason)
        if s is not None:
            v = auth.validate(s.token)
            log.info("request=validate(raced session) allowed=%s reason=%s", v.allowed, v.reason)
            assert not v.allowed and v.reason is DenialReason.SESSION_INVALIDATED
            r, _ = auth.refresh(s.token)
            assert not r.allowed and r.reason is DenialReason.SESSION_INVALIDATED
        else:
            assert d.reason is DenialReason.ACCOUNT_DISABLED
        # 停用完成后新登录也必须被挡
        d2, s2 = auth.login("alice", PASSWORDS["alice"])
        log.info("request=login(after disable) allowed=%s reason=%s", d2.allowed, d2.reason)
        assert not d2.allowed and d2.reason is DenialReason.ACCOUNT_DISABLED and s2 is None
    finally:
        accounts.set_enabled("alice", True)


def test_password_change_landing_between_authenticate_and_issue(auth, accounts, monkeypatch):
    """确定性复现：改密落在"旧口令认证通过"与"签发会话"之间，
    签发的会话必须不可用，旧口令之后也不能再登录。"""
    original = accounts.authenticate
    fired = []

    def authenticate_then_change(username, password):
        decision, account = original(username, password)
        if decision.allowed and not fired:
            fired.append(True)
            d = accounts.change_password("alice", "mid-flight-pw")  # 模拟并发改密在此刻完成
            log.info("request=change_password(alice, mid-login) detail=%s", d.detail)
        return decision, account

    monkeypatch.setattr(accounts, "authenticate", authenticate_then_change)
    try:
        d, s = auth.login("alice", PASSWORDS["alice"])  # 旧口令通过认证后口令被改
        log.info("request=login(raced with password change) allowed=%s reason=%s", d.allowed, d.reason)
        if s is not None:
            v = auth.validate(s.token)
            log.info("request=validate(raced session) allowed=%s reason=%s", v.allowed, v.reason)
            assert not v.allowed and v.reason is DenialReason.SESSION_INVALIDATED
        else:
            assert d.reason is DenialReason.PASSWORD_MISMATCH
        # 旧口令之后不能再登录，新口令可以
        d2, s2 = auth.login("alice", PASSWORDS["alice"])
        log.info("request=login(old password, after change) allowed=%s reason=%s", d2.allowed, d2.reason)
        assert not d2.allowed and d2.reason is DenialReason.PASSWORD_MISMATCH and s2 is None
        d3, s3 = auth.login("alice", "mid-flight-pw")
        assert d3.allowed and auth.validate(s3.token).allowed
    finally:
        accounts.change_password("alice", PASSWORDS["alice"])


def test_old_credentials_uniformly_rejected_after_disable(auth, accounts):
    """同一批旧凭据在停用完成后结论一致：访问与续期全部以 session_invalidated 拒绝，
    不允许有的成功有的失败。"""
    sessions = [do_login(auth, "alice") for _ in range(4)]
    d = accounts.set_enabled("alice", False)
    log.info("request=disable(alice) detail=%s", d.detail)
    assert d.allowed
    try:
        n = 32

        def probe(i):
            token = sessions[i % len(sessions)].token
            if i % 2 == 0:
                r = auth.validate(token)
                log.info("request=validate#%d allowed=%s reason=%s", i, r.allowed, r.reason)
                return r
            r, _ = auth.refresh(token)
            log.info("request=refresh#%d allowed=%s reason=%s", i, r.allowed, r.reason)
            return r

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(probe, range(n)))
        assert all(
            not r.allowed and r.reason is DenialReason.SESSION_INVALIDATED for r in results
        ), "停用完成后所有旧凭据请求必须一致地以 session_invalidated 拒绝"
        log.info("all %d mixed validate/refresh uniformly SESSION_INVALIDATED", n)
    finally:
        accounts.set_enabled("alice", True)
