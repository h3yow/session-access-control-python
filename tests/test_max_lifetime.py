"""续期总时长上限：刷新可延长活跃时间，但不能突破登录时刻算起的上限。

夹具参数：ttl=60s，max_lifetime=120s，时钟起点 t=1000。
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason
from tests.conftest import do_login

log = logging.getLogger("verify.max_lifetime")


def test_refresh_within_cap_extends_activity(auth, clock):
    s = do_login(auth, "alice")  # t=1000 登录，上限 1120
    clock.advance(50.0)          # t=1050
    d, ns = auth.refresh(s.token)
    log.info("request=refresh(t=1050) allowed=%s expires_at=%.0f", d.allowed, ns.expires_at)
    assert d.allowed and ns.expires_at == 1110.0  # 正常延长一个 ttl


def test_refresh_expiry_never_exceeds_absolute_cap(auth, clock):
    s = do_login(auth, "alice")
    clock.advance(50.0)          # t=1050
    d, ns = auth.refresh(s.token)
    assert d.allowed
    clock.advance(50.0)          # t=1100，距上限只剩 20s
    d, ns2 = auth.refresh(ns.token)
    log.info("request=refresh(t=1100) allowed=%s expires_at=%.0f (cap=1120)", d.allowed, ns2.expires_at)
    assert d.allowed
    assert ns2.expires_at == 1120.0, "新凭据有效期必须被截断到总时长上限"


def test_refresh_at_cap_rejected_with_distinct_reason(auth, clock):
    s = do_login(auth, "alice")
    clock.advance(50.0)
    d, ns = auth.refresh(s.token)
    assert d.allowed
    clock.advance(70.0)          # t=1120，恰好到达上限
    d, ns2 = auth.refresh(ns.token)
    log.info("request=refresh(t=1120, at cap) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.SESSION_MAX_AGE_EXCEEDED and ns2 is None


def test_max_age_reason_distinguishable_from_others(auth, accounts, clock):
    s_cap = do_login(auth, "alice")
    clock.advance(120.0)         # 到达上限（凭据同时也自然过期）
    d_refresh, _ = auth.refresh(s_cap.token)
    log.info("request=refresh(at cap) reason=%s", d_refresh.reason)
    assert d_refresh.reason is DenialReason.SESSION_MAX_AGE_EXCEEDED

    d_validate = auth.validate(s_cap.token)
    log.info("request=validate(at cap) reason=%s", d_validate.reason)
    assert d_validate.reason is DenialReason.SESSION_EXPIRED  # 访问侧仍是自然过期

    s2 = do_login(auth, "bob")
    auth.revoke(s2.session_id)
    d_revoked, _ = auth.refresh(s2.token)
    assert d_revoked.reason is DenialReason.SESSION_REVOKED

    s3 = do_login(auth, "carol")
    old_token = s3.token
    auth.refresh(old_token)
    d_rotated, _ = auth.refresh(old_token)  # 重放已轮换的旧凭据
    assert d_rotated.reason is DenialReason.TOKEN_ROTATED


def test_session_dies_at_cap_regardless_of_refresh(auth, clock):
    """无论怎么刷，1120 之后会话都不再有有效凭据。"""
    s = do_login(auth, "alice")
    token = s.token
    for hop in range(5):  # 每 20s 刷一次，试图无限续命
        clock.advance(20.0)
        d, ns = auth.refresh(token)
        log.info("request=refresh(hop=%d t=%.0f) allowed=%s reason=%s",
                 hop, clock.now, d.allowed, d.reason)
        if not d.allowed:
            assert d.reason is DenialReason.SESSION_MAX_AGE_EXCEEDED
            break
        token = ns.token
        assert ns.expires_at <= 1120.0
    clock.advance(120.0)
    d = auth.validate(token)
    log.info("request=validate(long past cap) reason=%s", d.reason)
    assert not d.allowed


def test_concurrent_refresh_near_cap_single_winner(auth, clock):
    """上限附近并发续期：恰好一个成功，其余结论一致，不留多个有效会话。"""
    s = do_login(auth, "alice")
    clock.advance(50.0)          # t=1050，上限 1120 之前最后一次续期窗口
    token = s.token
    n = 16
    barrier = threading.Barrier(n)

    def attempt(i):
        barrier.wait()
        d, ns = auth.refresh(token)
        log.info("request=refresh#%d(t=1050) allowed=%s reason=%s", i, d.allowed, d.reason)
        return d, ns

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    winners = [ns for d, ns in results if d.allowed]
    losers = [d for d, _ in results if not d.allowed]
    assert len(winners) == 1, "并发续期必须恰好一个成功"
    assert all(d.reason is DenialReason.TOKEN_ROTATED for d in losers), "失败者结论必须一致"
    winner_token = winners[0].token
    assert winners[0].expires_at <= 1120.0
    assert auth.validate(winner_token).allowed

    # 推进到上限后：胜出的凭据也无法再续期，且最终自然过期
    clock.advance(70.0)          # t=1120
    d, _ = auth.refresh(winner_token)
    log.info("request=refresh(winner at cap) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_MAX_AGE_EXCEEDED
    clock.advance(1.0)
    assert auth.validate(winner_token).reason is DenialReason.SESSION_EXPIRED
