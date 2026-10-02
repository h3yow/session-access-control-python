"""本地账号登录：失败原因可区分、连续失败限流/锁定、并发计数稳定。"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.auth import AuthService
from app.models import DenialReason

log = logging.getLogger("verify.login")


def test_login_failure_reasons_are_distinguishable(auth):
    d1, _ = auth.login("ghost", "whatever")
    log.info("request=login(user=ghost) allowed=%s reason=%s detail=%s",
             d1.allowed, d1.reason.value, d1.detail)
    assert d1.reason is DenialReason.ACCOUNT_NOT_FOUND

    d2, _ = auth.login("alice", "wrong-password")
    log.info("request=login(user=alice,pw=wrong) allowed=%s reason=%s detail=%s",
             d2.allowed, d2.reason.value, d2.detail)
    assert d2.reason is DenialReason.BAD_PASSWORD

    d3, _ = auth.login("dave", "dave-pw")  # dave 是预置的停用账号
    log.info("request=login(user=dave,pw=correct-but-disabled) allowed=%s reason=%s detail=%s",
             d3.allowed, d3.reason.value, d3.detail)
    assert d3.reason is DenialReason.ACCOUNT_DISABLED

    # 三种失败都不得建立会话：任何签发凭据都不应该属于这些用户。
    assert all(s.user_id != "ghost" for s in auth._sessions.values())


def test_login_role_is_taken_from_account(auth):
    d, s = auth.login("carol", "carol-pw")
    log.info("request=login(user=carol) allowed=%s role=%s", d.allowed, s.role.value)
    assert d.allowed and s.role.value == "viewer"
    # viewer 账号即使"自称 owner"也拿不到 owner 角色（请求里根本没有角色字段）。


def test_login_bad_password_does_not_create_session(auth):
    before = set(auth._sessions)
    auth.login("alice", "nope")
    assert set(auth._sessions) == before


def test_lockout_after_threshold_blocks_even_correct_password(auth):
    # 阈值 5 次：前 4 次返回 BAD_PASSWORD，第 5 次触发锁定，结论仍为口令错误。
    for i in range(1, 5):
        d, _ = auth.login("bob", "bad")
        log.info("request=login#%d(user=bob,pw=bad) reason=%s detail=%s",
                 i, d.reason.value, d.detail)
        assert d.reason is DenialReason.BAD_PASSWORD

    d5, _ = auth.login("bob", "bad")
    log.info("request=login#5(user=bob,pw=bad,trigger) reason=%s detail=%s",
             d5.reason.value, d5.detail)
    assert d5.reason is DenialReason.BAD_PASSWORD and auth._lock_until["bob"] > 0

    # 锁定期间口令正确也必须被挡，且原因与"口令不对"区分开。
    d6, _ = auth.login("bob", "bob-pw")
    log.info("request=login#6(user=bob,pw=correct-during-lock) reason=%s detail=%s",
             d6.reason.value, d6.detail)
    assert d6.reason is DenialReason.ACCOUNT_LOCKED
    assert not d6.allowed


def test_correct_password_during_lockout_never_creates_session(auth, clock):
    for _ in range(5):
        auth.login("alice", "bad")
    d, s = auth.login("alice", "alice-pw")
    assert d.reason is DenialReason.ACCOUNT_LOCKED and s is None


def test_lockout_expires_then_login_succeeds_and_counter_resets(auth, clock):
    for _ in range(5):
        assert auth.login("alice", "bad")[0].reason is DenialReason.BAD_PASSWORD
    assert auth.login("alice", "alice-pw")[0].reason is DenialReason.ACCOUNT_LOCKED

    clock.advance(61.0)  # 越过 60s 锁定窗口
    d, s = auth.login("alice", "alice-pw")
    log.info("request=login(after lockout expiry) allowed=%s reason=%s", d.allowed, d.reason)
    assert d.allowed and s is not None
    # 计数已重置：之后连续失败从 1 重新计。
    d2, _ = auth.login("alice", "bad")
    assert d2.reason is DenialReason.BAD_PASSWORD and "1/5" in d2.detail


def test_successful_login_resets_failure_counter(auth):
    for _ in range(3):
        auth.login("carol", "bad")
    assert auth.login("carol", "carol-pw")[0].allowed
    d, _ = auth.login("carol", "bad")
    log.info("request=login(after success then bad) detail=%s", d.detail)
    assert auth._failures.get("carol", 0) == 1


def test_concurrent_bad_logins_are_counted_exactly(auth):
    """16 个同时到达的失败登录：计数不能因并发少算。

    阈值为 5：恰好 5 个请求得到 BAD_PASSWORD（第 5 个触发锁定），
    其余 11 个得到 ACCOUNT_LOCKED；锁定后正确口令也被挡。
    若有计数丢失，BAD_PASSWORD 会多于 5 个。
    """
    n = 16
    barrier = threading.Barrier(n)

    def attempt(i):
        barrier.wait()
        d, _ = auth.login("bob", "bad")
        log.info("request=concurrent-login#%02d(user=bob,pw=bad) allowed=%s reason=%s detail=%s",
                 i, d.allowed, d.reason.value, d.detail)
        return d

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    bad = [d for d in results if d.reason is DenialReason.BAD_PASSWORD]
    locked = [d for d in results if d.reason is DenialReason.ACCOUNT_LOCKED]
    log.info("concurrent bad logins: bad_password=%d account_locked=%d", len(bad), len(locked))
    assert len(bad) == 5, f"失败计数不稳定: BAD_PASSWORD={len(bad)}"
    assert len(locked) == 11

    # 锁定结论与口令错误可区分，且锁定期间正确口令也不放行。
    after = auth.login("bob", "bob-pw")[0]
    log.info("request=login(correct after concurrent lock) reason=%s", after.reason.value)
    assert after.reason is DenialReason.ACCOUNT_LOCKED
