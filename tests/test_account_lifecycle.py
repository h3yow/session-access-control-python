"""账号状态变化联动：停用 / 改口令后，旧会话立即失去访问与续期能力，
并发下不允许状态切换完成后还有请求漏网成功；原因须与撤销/过期区分。"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason

log = logging.getLogger("verify.account")

# 每个并发工作线程在竞态窗口内执行的有界请求数（不使用忙等事件，避免饥饿）。
_RACE_ITERS = 50


def _login(auth, user="alice", pw=None):
    d, s = auth.login(user, pw or f"{user}-pw")
    assert d.allowed, d.detail
    return s


def test_disabled_account_old_session_fails_everywhere(auth):
    s = _login(auth, "alice")
    d = auth.disable_account("alice")
    assert d.allowed

    d_validate = auth.validate(s.token)
    log.info("request=validate(after disable) reason=%s detail=%s",
             d_validate.reason.value, d_validate.detail)
    assert d_validate.reason is DenialReason.ACCOUNT_STATE_CHANGED

    d_refresh, ns = auth.refresh(s.token)
    log.info("request=refresh(after disable) reason=%s", d_refresh.reason.value)
    assert d_refresh.reason is DenialReason.ACCOUNT_STATE_CHANGED and ns is None

    d_login = auth.login("alice", "alice-pw")[0]
    log.info("request=login(disabled user) reason=%s", d_login.reason.value)
    assert d_login.reason is DenialReason.ACCOUNT_DISABLED


def test_disable_is_distinguishable_from_revoke_and_expiry(auth):
    s1 = _login(auth, "alice")
    s2 = _login(auth, "bob")
    auth.revoke(s1.session_id)
    auth.disable_account("bob")
    assert auth.validate(s1.token).reason is DenialReason.SESSION_REVOKED
    r = auth.validate(s2.token)
    log.info("request=validate(revoked=%s vs state-changed=%s)",
             DenialReason.SESSION_REVOKED.value, r.reason.value)
    assert r.reason is DenialReason.ACCOUNT_STATE_CHANGED


def test_all_old_sessions_fail_uniformly_after_disable(auth):
    """同一批旧凭据：停用后所有请求结论一致，不允许有的成功有的失败。"""
    sessions = [_login(auth, "alice") for _ in range(4)]
    auth.disable_account("alice")
    reasons = []
    for i, s in enumerate(sessions):
        d = auth.validate(s.token)
        log.info("request=validate#%d(after disable) reason=%s", i, d.reason.value)
        reasons.append(d.reason)
    assert reasons == [DenialReason.ACCOUNT_STATE_CHANGED] * len(sessions)


def test_re_enable_does_not_revive_old_sessions(auth):
    s = _login(auth, "alice")
    auth.disable_account("alice")
    auth.enable_account("alice")
    r = auth.validate(s.token)
    log.info("request=validate(after re-enable old token) reason=%s", r.reason.value)
    assert r.reason is DenialReason.ACCOUNT_STATE_CHANGED
    d, s2 = auth.login("alice", "alice-pw")
    assert d.allowed and auth.validate(s2.token).allowed


def test_password_change_invalidates_old_sessions(auth):
    s = _login(auth, "alice")
    d = auth.change_account_password("alice", "brand-new-pw")
    assert d.allowed

    r1 = auth.validate(s.token)
    log.info("request=validate(after pw change) reason=%s detail=%s",
             r1.reason.value, r1.detail)
    assert r1.reason is DenialReason.ACCOUNT_STATE_CHANGED
    r2, _ = auth.refresh(s.token)
    assert r2.reason is DenialReason.ACCOUNT_STATE_CHANGED

    assert auth.login("alice", "alice-pw")[0].reason is DenialReason.BAD_PASSWORD
    d2, s2 = auth.login("alice", "brand-new-pw")
    assert d2.allowed and auth.validate(s2.token).allowed


def test_password_change_only_affects_target_account(auth):
    sa = _login(auth, "alice")
    sb = _login(auth, "bob")
    auth.change_account_password("alice", "new")
    assert auth.validate(sa.token).reason is DenialReason.ACCOUNT_STATE_CHANGED
    log.info("request=validate(bob unaffected) allowed=%s", auth.validate(sb.token).allowed)
    assert auth.validate(sb.token).allowed


def test_concurrent_validate_around_disable_no_success_after(auth):
    """状态切换与并发请求同时发生：停用完成后不允许任何请求漏网成功。

    结构（确定性、有界，无忙等）：
    1. n 个工作线程与主线程在同一屏障集合，同时放行；
    2. 工作线程对旧凭据各执行有限次 validate；主线程放行后立刻执行停用；
    3. 收口：停用确定已完成后，每个工作线程再校验一次，必须全部
       得到 ACCOUNT_STATE_CHANGED。竞态窗口内只允许出现
       "允许（停用前）" 或 "状态已变化（停用后）" 两种结论。
    """
    s = _login(auth, "alice")
    token = s.token
    n = 16
    gate = threading.Barrier(n + 1)
    racy: list[tuple[int, bool, object]] = []
    finals: list[tuple[int, object]] = []
    rec_lock = threading.Lock()

    def worker(i):
        gate.wait()
        local = []
        for k in range(_RACE_ITERS):
            d = auth.validate(token)
            local.append((k, d.allowed, d.reason))
        return i, local

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futures = [pool.submit(worker, i) for i in range(n)]
        gate.wait()  # 与工作线程同时放行
        disable_decision = auth.disable_account("alice")
        log.info("request=disable(raced) %s", disable_decision.detail)
        for f in futures:
            i, local = f.result()
            with rec_lock:
                racy.extend((i, *r) for r in local)
                finals.append((i, auth.validate(token)))

    # 竞态窗口：任何被拒结论都只能是"账号状态已变化"。
    for i, k, allowed, reason in racy:
        if not allowed:
            assert reason is DenialReason.ACCOUNT_STATE_CHANGED, (i, k, reason)
    # 收口（停用一定已完成）：全部一致，零漏网成功。
    after_allowed = 0
    for i, d in finals:
        log.info("request=final-validate#%02d allowed=%s reason=%s",
                 i, d.allowed, d.reason.value if d.reason else None)
        if d.allowed:
            after_allowed += 1
    assert after_allowed == 0, "停用完成后存在漏网成功请求"
    assert all(d.reason is DenialReason.ACCOUNT_STATE_CHANGED for _, d in finals)
    assert disable_decision.allowed


def test_concurrent_requests_around_password_change_no_success_after(auth):
    """改口令与并发访问/续期同时发生：收口后旧凭据的访问与续期必须
    全部以 ACCOUNT_STATE_CHANGED 失败，且不允许并存多个有效新会话。"""
    s = _login(auth, "alice")
    token = s.token
    n = 16
    gate = threading.Barrier(n + 1)

    def worker(i):
        gate.wait()
        local = []
        for k in range(_RACE_ITERS):
            dv = auth.validate(token)
            dr, _ = auth.refresh(token)
            local.append((k, dv, dr))
        return i, local

    with ThreadPoolExecutor(max_workers=n + 1) as pool:
        futures = [pool.submit(worker, i) for i in range(n)]
        gate.wait()
        change = auth.change_account_password("alice", "rotated-pw")
        gathered = [f.result() for f in futures]

    assert change.allowed
    # 收口：改口令确定已完成，旧凭据访问与续期一律失效、原因一致。
    final_validate = auth.validate(token)
    final_refresh, ns = auth.refresh(token)
    log.info("post-change converge: validate=%s refresh=%s new_session=%s",
             final_validate.reason.value, final_refresh.reason.value, ns)
    assert final_validate.reason is DenialReason.ACCOUNT_STATE_CHANGED
    assert final_refresh.reason is DenialReason.ACCOUNT_STATE_CHANGED and ns is None

    # 竞态窗口内：validate 只可能成功或状态变化；refresh 只可能成功一次
    # （之后为 TOKEN_ROTATED）或状态变化；不允许出现其它原因。
    refresh_successes = 0
    allowed_reasons = {None, DenialReason.TOKEN_ROTATED, DenialReason.ACCOUNT_STATE_CHANGED}
    for i, local in gathered:
        for k, dv, dr in local:
            log.info("request=race#%02d-%02d validate=%s refresh=%s",
                     i, k, dv.reason, dr.reason)
            assert dv.reason in (None, DenialReason.ACCOUNT_STATE_CHANGED)
            assert dr.reason in allowed_reasons
            if dr.allowed:
                refresh_successes += 1
    # 续期在竞态窗口内最多成功一次（单锁串行化），不会并存多个有效会话。
    assert refresh_successes <= 1
