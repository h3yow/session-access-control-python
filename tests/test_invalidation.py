"""账号状态变化（停用/改密）联动既有会话失效：立即生效、原因可区分、并发不漏网。"""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason, Role
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


def test_concurrent_logins_against_disable_leave_no_usable_session(auth, accounts):
    """停用与"用旧凭据并发登录 + 持旧会话并发续期"同时发生的高压场景。

    多个 worker 在停止信号前一直用正确口令登录并尝试续期；主线程等大量登录
    正在途时执行停用。断言：
    1. 风暴中签发过的每一张凭据（含续期新凭据），停用完成后一律不可用；
    2. 同一张旧凭据的并发结论一致（允许或 SESSION_INVALIDATED，不允许夹生）；
    3. 停用完成后再用旧凭据登录，稳定得到 account_disabled，绝不再拿到会话。
    """
    n = 12
    stop = threading.Event()
    issued: list[str] = []
    issued_lock = threading.Lock()
    decisions: list[tuple[str, object]] = []

    def worker(i):
        local = 0
        while not stop.is_set():
            d, s = auth.login("alice", PASSWORDS["alice"])
            if not d.allowed:
                # 停用生效后的登录必须明确是"账号已停用"，不允许其他结论
                log.info("request=login#%d denied reason=%s", i, d.reason)
                assert d.reason is DenialReason.ACCOUNT_DISABLED
                continue
            with issued_lock:
                issued.append(s.token)
            # 拿到会话立刻续期，制造"认证→签发→续期"与停用交错的窗口
            d2, s2 = auth.refresh(s.token)
            if d2.allowed:
                with issued_lock:
                    issued.append(s2.token)
                local += 1
            else:
                assert d2.reason is DenialReason.SESSION_INVALIDATED, d2.reason
        return local

    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(worker, i) for i in range(n)]
        # 让登录先跑起来（大量认证/签发正在途），再完成停用
        time.sleep(0.05)
        d = accounts.set_enabled("alice", False)
        log.info("request=disable(alice) in storm detail=%s", d.detail)
        assert d.allowed
        stop.set()
        total_refreshes = sum(f.result() for f in futs)

    # 1) 停用完成后：风暴中签发过的所有凭据一律 SESSION_INVALIDATED，无一可用
    usable = []
    for t in issued:
        vd = auth.validate(t)
        if vd.allowed:
            usable.append(t)
    log.info("after disable storm: issued=%d usable=%d refreshes=%d",
             len(issued), len(usable), total_refreshes)
    assert not usable, f"停用后仍有 {len(usable)} 张凭据可用"

    # 2) 对同一张旧凭据发起并发访问，结论必须一致（全部 SESSION_INVALIDATED）
    if issued:
        token = issued[0]
        m = 16
        barrier = threading.Barrier(m)

        def probe(j):
            barrier.wait()
            vd = auth.validate(token)
            decisions.append((j, vd.reason))
            return vd

        with ThreadPoolExecutor(max_workers=m) as pool2:
            verdicts = list(pool2.map(probe, range(m)))
        assert all(not v.allowed and v.reason is DenialReason.SESSION_INVALIDATED
                   for v in verdicts), "同批旧凭据结论不一致"
        log.info("concurrent probe on stale token: %d/%d SESSION_INVALIDATED",
                 len(verdicts), m)

    # 3) 停用完成后旧凭据登录稳定被 account_disabled 挡住
    for k in range(8):
        d, s = auth.login("alice", PASSWORDS["alice"])
        log.info("request=login#%d(after disable) reason=%s", k, d.reason)
        assert not d.allowed and d.reason is DenialReason.ACCOUNT_DISABLED and s is None


def test_concurrent_logins_against_password_change_leave_no_usable_session(clock):
    """改口令与并发登录/续期同时发生：切换完成后旧凭据不再可用、旧口令不能再登录。

    使用独立服务并把失败上限调到远高于请求总数，避免锁定干扰对"旧口令"判定的观察。
    """
    from app.accounts import AccountStore
    from app.auth import AuthService

    store = AccountStore(max_failures=10_000, lockout_seconds=30.0, clock=clock)
    store.add_account("victim", "old-pw", Role.OWNER)
    svc = AuthService(store, ttl_seconds=60.0, max_lifetime_seconds=120.0, clock=clock)

    n = 12
    stop = threading.Event()
    issued: list[str] = []
    issued_lock = threading.Lock()

    def worker(i):
        while not stop.is_set():
            d, s = svc.login("victim", "old-pw")
            if not d.allowed:
                log.info("request=login#%d(old pw) denied reason=%s", i, d.reason)
                # 改密后旧口令必须是"口令不匹配"，而不是锁定或别的原因
                assert d.reason is DenialReason.PASSWORD_MISMATCH
                continue
            with issued_lock:
                issued.append(s.token)
            d2, s2 = svc.refresh(s.token)
            if d2.allowed:
                with issued_lock:
                    issued.append(s2.token)
            else:
                assert d2.reason is DenialReason.SESSION_INVALIDATED, d2.reason

    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(worker, i) for i in range(n)]
        time.sleep(0.05)
        d = store.change_password("victim", "brand-new-pw")
        log.info("request=change_password(victim) in storm detail=%s", d.detail)
        assert d.allowed
        stop.set()
        for f in futs:
            f.result()

    # 改密完成后，风暴中签发过的全部凭据（含竞争中续期出的新凭据）一律失效
    usable = [t for t in issued if svc.validate(t).allowed]
    log.info("after password-change storm: issued=%d usable=%d", len(issued), len(usable))
    assert not usable, f"改密后仍有 {len(usable)} 张凭据可用"
    for t in issued:
        vd = svc.validate(t)
        assert not vd.allowed and vd.reason is DenialReason.SESSION_INVALIDATED

    # 旧口令并发登录：全部 password_mismatch，且不能留下任何会话
    m = 16
    barrier = threading.Barrier(m)

    def old_pw_login(j):
        barrier.wait()
        d, s = svc.login("victim", "old-pw")
        log.info("request=login#%d(old pw after change) reason=%s", j, d.reason)
        return d, s

    with ThreadPoolExecutor(max_workers=m) as pool2:
        results = list(pool2.map(old_pw_login, range(m)))
    assert all(not d.allowed and d.reason is DenialReason.PASSWORD_MISMATCH and s is None
               for d, s in results), "旧口令并发登录结论必须一致且不建立会话"

    # 新口令可正常登录，且新会话可用
    d, s_new = svc.login("victim", "brand-new-pw")
    log.info("request=login(new pw) allowed=%s", d.allowed)
    assert d.allowed and svc.validate(s_new.token).allowed
