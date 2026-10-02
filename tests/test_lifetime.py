"""会话续期总时长上限：刷新只能延长滑动活跃时间，不能突破登录时刻起算的
绝对上限；到达上限后续期被明确拒绝，原因与普通过期/撤销/轮换区分；
上限附近的并发续期结论确定，只可能有一个成功且不留多个有效会话。"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason

log = logging.getLogger("verify.lifetime")


def _login(auth, user="alice"):
    d, s = auth.login(user, f"{user}-pw")
    assert d.allowed, d.detail
    return s


def test_refresh_cannot_break_absolute_lifetime_cap(auth, clock):
    """TTL=60，绝对上限=200：连续刷新不能把有效期推过登录后 200s。"""
    s = _login(auth)
    token_chain = [s.token]
    # 每次推进 55s 再刷新（滑动窗口内），理论上无上限时会无限续命。
    for i in range(3):
        clock.advance(55.0)  # 55 / 110 / 165
        d, s = auth.refresh(s.token)
        log.info("request=refresh#%d(t=%g) allowed=%s expiry=%g cap=%g",
                 i + 1, clock.now - 1000.0, d.allowed, s.expires_at, s.absolute_expires_at)
        assert d.allowed
        token_chain.append(s.token)

    clock.advance(36.0)  # t=201 > 绝对上限 200
    d = auth.validate(s.token)
    log.info("request=validate(t=201) reason=%s detail=%s", d.reason.value, d.detail)
    assert d.reason is DenialReason.SESSION_LIFETIME_EXCEEDED

    # 到期后续期请求被明确拒绝，原因与普通过期区分。
    dr, ns = auth.refresh(s.token)
    log.info("request=refresh(at/over cap) reason=%s", dr.reason.value)
    assert dr.reason is DenialReason.SESSION_LIFETIME_EXCEEDED and ns is None

    # 所有沿轮换链产生的旧凭据结论保持各自语义（已轮换），不复活。
    assert auth.validate(token_chain[0]).reason is DenialReason.TOKEN_ROTATED


def test_cap_reason_distinguishable_from_sliding_expiry_and_revoke(auth, clock):
    s1 = _login(auth, "alice")
    s2 = _login(auth, "bob")
    auth.revoke(s2.session_id)
    clock.advance(61.0)  # s1 滑动过期但远未到绝对上限
    assert auth.validate(s1.token).reason is DenialReason.SESSION_EXPIRED
    assert auth.validate(s2.token).reason is DenialReason.SESSION_REVOKED

    s3 = _login(auth, "carol")
    clock.advance(201.0)
    r = auth.validate(s3.token)
    log.info("request=validate(expired=%s revoked=%s cap=%s)",
             DenialReason.SESSION_EXPIRED.value,
             DenialReason.SESSION_REVOKED.value, r.reason.value)
    assert r.reason is DenialReason.SESSION_LIFETIME_EXCEEDED


def _keep_alive(auth, clock, s, points=(50.0, 100.0, 150.0)):
    """以小于 TTL(60s) 的间隔刷新，把会话活跃地维持到 t=150（此时滑动
    过期点已被截到绝对上限 t=200），返回最新会话。"""
    for target in points:
        clock.now = 1000.0 + target
        d, s = auth.refresh(s.token)
        assert d.allowed, (target, d.reason)
    return s


def test_refresh_near_cap_clamps_to_cap(auth, clock):
    """剩余时长不足一个 TTL 时，刷新把滑动过期点截到绝对上限而不是+TTL。"""
    s = _keep_alive(auth, clock, _login(auth))
    clock.advance(30.0)  # t=180，距上限剩 20s，凭据仍在滑动窗口内
    d, ns = auth.refresh(s.token)
    assert d.allowed
    log.info("request=refresh(near cap) expiry=%g cap=%g", ns.expires_at, ns.absolute_expires_at)
    assert ns.expires_at == ns.absolute_expires_at
    clock.advance(19.0)
    assert auth.validate(ns.token).allowed  # 上限内仍有效
    clock.advance(2.0)  # 越过上限
    assert auth.validate(ns.token).reason is DenialReason.SESSION_LIFETIME_EXCEEDED


def test_refresh_at_exactly_the_cap_is_rejected(auth, clock):
    """now >= absolute_expires_at 即到上限（边界含等号）。"""
    s = _keep_alive(auth, clock, _login(auth))
    clock.advance(40.0)  # t=190，再刷新一次把 expiry 截到上限点
    d, s = auth.refresh(s.token)
    assert d.allowed and s.expires_at == s.absolute_expires_at
    clock.now = s.absolute_expires_at
    r1 = auth.validate(s.token)
    r2, ns = auth.refresh(s.token)
    log.info("request=at exact cap validate=%s refresh=%s", r1.reason.value, r2.reason.value)
    assert r1.reason is DenialReason.SESSION_LIFETIME_EXCEEDED
    assert r2.reason is DenialReason.SESSION_LIFETIME_EXCEEDED and ns is None


def test_concurrent_refresh_near_cap_only_one_succeeds(auth, clock):
    """上限附近并发续期：恰好一个成功，其余结论确定一致，不留多个有效会话。

    选择 t=190（距上限 10s < TTL）：一个请求成功续期（截到上限），
    其余全部因凭据已轮换失败；成功后再统一推进到上限，所有凭据都以
    SESSION_LIFETIME_EXCEEDED 收口。
    """
    s = _keep_alive(auth, clock, _login(auth))
    clock.advance(40.0)  # t=190，距上限 10s，所有并发请求在此刻同时发出
    old_token = s.token
    n = 24
    barrier = threading.Barrier(n)

    def attempt(i):
        barrier.wait()
        d, ns = auth.refresh(old_token)
        log.info("request=refresh-near-cap#%02d allowed=%s reason=%s",
                 i, d.allowed, d.reason.value if d.reason else None)
        return d, ns

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    successes = [r for r in results if r[0].allowed]
    failures = [r for r in results if not r[0].allowed]
    assert len(successes) == 1, "上限附近并发续期必须恰好一个成功"
    assert all(d.reason is DenialReason.TOKEN_ROTATED for d, _ in failures)
    new_token = successes[0][1].token
    assert auth.validate(new_token).allowed
    log.info("near-cap concurrent refresh: 1 success, %d TOKEN_ROTATED", len(failures))

    # 越过绝对上限后收口：新旧凭据都不能再访问或续期，结论一致。
    clock.advance(11.0)
    final_old = auth.validate(old_token)
    final_new = auth.validate(new_token)
    log.info("post-cap: old=%s new=%s", final_old.reason.value, final_new.reason.value)
    assert final_old.reason is DenialReason.TOKEN_ROTATED  # 旧凭据仍是轮换语义
    assert final_new.reason is DenialReason.SESSION_LIFETIME_EXCEEDED
    assert auth.refresh(new_token)[0].reason is DenialReason.SESSION_LIFETIME_EXCEEDED


def test_concurrent_refresh_at_cap_all_rejected_consistently(auth, clock):
    """所有并发请求都发生在上限点或之后：全部被拒且原因一致，零会话产生。"""
    s = _login(auth)
    old_token = s.token
    clock.now = s.absolute_expires_at  # 精确到上限
    n = 16
    barrier = threading.Barrier(n)
    sessions_before = set(auth._sessions[old_token and s.session_id]) if False else None

    def attempt(i):
        barrier.wait()
        d, ns = auth.refresh(old_token)
        log.info("request=refresh-at-cap#%02d allowed=%s reason=%s session=%s",
                 i, d.allowed, d.reason.value, ns is not None)
        return d, ns

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    assert all(not d.allowed for d, _ in results)
    assert all(ns is None for _, ns in results)
    assert all(d.reason is DenialReason.SESSION_LIFETIME_EXCEEDED for d, _ in results)
    # 原会话仍只有一条记录，没有产生任何并行有效会话。
    assert len(auth._sessions) == 1


def test_account_state_change_outranks_lifetime_cap(auth, clock):
    """同一旧会话同时满足"账号状态变化"与"超过上限"时，状态变化优先，
    保证账号侧结论不被时间原因掩盖。"""
    s = _login(auth, "alice")
    clock.advance(201.0)
    auth.disable_account("alice")
    r = auth.validate(s.token)
    log.info("request=validate(cap+disabled) reason=%s", r.reason.value)
    assert r.reason is DenialReason.ACCOUNT_STATE_CHANGED
