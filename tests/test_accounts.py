"""本地账号登录：失败原因可区分、连续失败限流锁定、并发下计数与锁定稳定。"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason
from tests.conftest import PASSWORDS, do_login

log = logging.getLogger("verify.accounts")


def test_login_failure_reasons_distinguishable(auth):
    d, s = auth.login("nobody", "whatever")
    log.info("request=login(unknown user) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.ACCOUNT_UNKNOWN and s is None

    d, s = auth.login("alice", "wrong-pw")
    log.info("request=login(wrong password) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.PASSWORD_MISMATCH and s is None

    d, s = auth.login("dave", PASSWORDS["dave"])  # 停用账号，口令正确也拒绝
    log.info("request=login(disabled, correct pw) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.ACCOUNT_DISABLED and s is None


def test_failed_logins_establish_no_session(auth):
    d, _ = auth.login("alice", "wrong-pw")
    assert not d.allowed
    # 失败登录不应产生任何可用凭据：会话仓库保持为空
    assert not auth._sessions


def test_lockout_after_max_failures(auth, accounts, clock):
    for i in range(3):  # max_failures = 3
        d, _ = auth.login("alice", "wrong-pw")
        log.info("request=login(wrong #%d) reason=%s detail=%s", i + 1, d.reason, d.detail)
        assert d.reason is DenialReason.PASSWORD_MISMATCH

    # 锁定期间：口令正确也被挡住，且结论与"口令不对"区分
    d, _ = auth.login("alice", PASSWORDS["alice"])
    log.info("request=login(correct pw, locked) reason=%s detail=%s", d.reason, d.detail)
    assert d.reason is DenialReason.ACCOUNT_LOCKED

    # 锁定期满后恢复可登录
    clock.advance(31.0)
    d, s = auth.login("alice", PASSWORDS["alice"])
    log.info("request=login(after lockout) allowed=%s", d.allowed)
    assert d.allowed and s is not None


def test_successful_login_resets_failure_count(auth, accounts):
    for _ in range(2):  # 差一次到达上限
        auth.login("alice", "wrong-pw")
    do_login(auth, "alice")  # 成功登录清零计数
    d, _ = auth.login("alice", "wrong-pw")
    log.info("request=login(wrong after success) reason=%s detail=%s", d.reason, d.detail)
    assert d.reason is DenialReason.PASSWORD_MISMATCH  # 重新从 1 计起，未锁定
    d, _ = auth.login("alice", PASSWORDS["alice"])
    assert d.allowed  # 未进入锁定


def test_unknown_user_does_not_consume_throttle(auth):
    for _ in range(10):
        d, _ = auth.login("nobody", "x")
        assert d.reason is DenialReason.ACCOUNT_UNKNOWN
    d, s = auth.login("alice", PASSWORDS["alice"])
    log.info("request=login(after unknown-user attempts) allowed=%s", d.allowed)
    assert d.allowed  # 未知用户的尝试不影响真实账号


def test_concurrent_failed_logins_counted_and_locked(auth, accounts, clock):
    """并发失败：计数不少算，达到上限即锁定，锁定后正确口令也进不来。"""
    n = 12  # 远超上限 3
    barrier = threading.Barrier(n)

    def attempt(i):
        barrier.wait()
        d, _ = auth.login("alice", "wrong-pw")
        log.info("request=login#%d(wrong) reason=%s detail=%s", i, d.reason, d.detail)
        return d

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    mismatch = sum(1 for d in results if d.reason is DenialReason.PASSWORD_MISMATCH)
    locked = sum(1 for d in results if d.reason is DenialReason.ACCOUNT_LOCKED)
    log.info("concurrent failures: mismatch=%d locked=%d total=%d", mismatch, locked, n)
    assert mismatch + locked == n
    assert mismatch >= 3, "至少计满上限次数"
    assert locked >= 1, "超过上限的并发请求应看到锁定"

    # 并发风暴结束后账号确定处于锁定中：正确口令也被拒
    d, _ = auth.login("alice", PASSWORDS["alice"])
    log.info("request=login(correct pw after storm) reason=%s", d.reason)
    assert d.reason is DenialReason.ACCOUNT_LOCKED


def test_concurrent_mixed_success_and_failure_stable(clock):
    """正确口令与错误口令并发到达：每次判定都落在锁内，结论确定。"""
    from app.accounts import AccountStore
    from app.auth import AuthService
    from app.models import Role

    # 上限高于失败总数，排除锁定干扰，专注验证计数与判定在并发下不错乱
    store = AccountStore(max_failures=100, lockout_seconds=30.0, clock=clock)
    store.add_account("bob", PASSWORDS["bob"], Role.OWNER)
    auth = AuthService(store, ttl_seconds=60.0, max_lifetime_seconds=120.0, clock=clock)

    n = 10
    barrier = threading.Barrier(n)

    def attempt(i):
        barrier.wait()
        pw = PASSWORDS["bob"] if i % 2 == 0 else "wrong-pw"
        d, s = auth.login("bob", pw)
        log.info("request=login#%d(pw=%s) allowed=%s reason=%s",
                 i, "correct" if i % 2 == 0 else "wrong", d.allowed, d.reason)
        return d

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    # 5 次成功交错重置计数，失败次数始终到不了上限，不应出现锁定
    assert sum(1 for d in results if d.allowed) == 5
    assert all(d.reason is DenialReason.PASSWORD_MISMATCH for d in results if not d.allowed)
