"""并发与保护校验：并发刷新仅一个成功、旧凭据重放被拒、受保护写不丢更新。"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import DenialReason

log = logging.getLogger("verify.concurrency")


def test_concurrent_refresh_only_one_succeeds(auth):
    ok, s = auth.login("alice", "alice-pw")
    assert ok.allowed
    old_token = s.token
    n = 16
    barrier = threading.Barrier(n)

    def attempt(i):
        barrier.wait()  # 同时放行，最大化竞争
        d, ns = auth.refresh(old_token)
        log.info("request=refresh#%d allowed=%s reason=%s", i, d.allowed, d.reason)
        return d, ns

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    successes = [r for r in results if r[0].allowed]
    failures = [r for r in results if not r[0].allowed]
    assert len(successes) == 1, "并发刷新必须恰好一个成功"
    assert all(d.reason is DenialReason.TOKEN_ROTATED for d, _ in failures)
    new_token = successes[0][1].token
    assert auth.validate(new_token).allowed
    log.info("concurrent refresh: 1 success, %d rejected as TOKEN_ROTATED", len(failures))


def test_old_token_replay_after_refresh(auth):
    ok, s = auth.login("alice", "alice-pw")
    assert ok.allowed
    old_token = s.token
    auth.refresh(old_token)
    d = auth.refresh(old_token)  # 重放旧凭据再次刷新
    log.info("request=replay refresh(old) reason=%s", d[0].reason)
    assert not d[0].allowed and d[0].reason is DenialReason.TOKEN_ROTATED


def test_protected_write_rejections_make_no_change(auth):
    ok, s = auth.login("alice", "alice-pw")
    assert ok.allowed
    marker = []
    d = auth.update_session(s.token, None, None, lambda sess: marker.append(1))
    log.info("request=update(csrf=None) reason=%s", d.reason)
    assert d.reason is DenialReason.CSRF_MISSING and not marker

    d = auth.update_session(s.token, "wrong-csrf", None, lambda sess: marker.append(1))
    log.info("request=update(csrf=wrong) reason=%s", d.reason)
    assert d.reason is DenialReason.CSRF_MISMATCH and not marker

    d = auth.update_session(s.token, s.csrf_token, expected_version=99, mutate=lambda sess: marker.append(1))
    log.info("request=update(version=99) reason=%s detail=%s", d.reason, d.detail)
    assert d.reason is DenialReason.VERSION_CONFLICT and not marker


def test_concurrent_updates_no_lost_writes(auth):
    ok, s = auth.login("alice", "alice-pw")
    assert ok.allowed
    n = 32
    barrier = threading.Barrier(n)

    def bump(i):
        barrier.wait()
        d = auth.update_session(
            s.token, s.csrf_token, None,
            lambda sess: setattr(sess, "counter", getattr(sess, "counter", 0) + 1),
        )
        assert d.allowed  # 不带版本约束的更新都应在锁内串行成功
        return d

    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(bump, range(n)))

    final = auth.get_active_session(s.token)
    log.info("concurrent updates: version=%s counter=%s", final.version, final.counter)
    assert final.version == n and final.counter == n


def test_optimistic_version_conflict_under_concurrency(auth):
    """两个请求读到同一版本，只有一个能写入，另一个得到 VERSION_CONFLICT。"""
    ok, s = auth.login("alice", "alice-pw")
    assert ok.allowed
    base_version = s.version
    barrier = threading.Barrier(2)

    def attempt(i):
        barrier.wait()
        d = auth.update_session(
            s.token, s.csrf_token, base_version,
            lambda sess: setattr(sess, "winner", i),
        )
        log.info("request=update#%d(version=%d) allowed=%s reason=%s", i, base_version, d.allowed, d.reason)
        return d

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))

    assert sum(1 for d in results if d.allowed) == 1
    assert sum(1 for d in results if d.reason is DenialReason.VERSION_CONFLICT) == 1


def test_protected_write_positive_takes_effect_and_reads_back(auth):
    """正向分支：CSRF 与版本都正确时写入必须真正生效，随后能读到新内容。"""
    ok, s = auth.login("alice", "alice-pw")
    assert ok.allowed

    d1 = auth.update_session(
        s.token, s.csrf_token, s.version,
        lambda sess: setattr(sess, "profile", {"city": "Shanghai"}),
    )
    log.info("request=update(valid v=%d) allowed=%s detail=%s", s.version, d1.allowed, d1.detail)
    assert d1.allowed

    live = auth.get_active_session(s.token)
    log.info("readback profile=%s version=%s", getattr(live, "profile", None), live.version)
    assert live.version == 1 and live.profile == {"city": "Shanghai"}

    # 带新版本号的第二次写入同样成功且读回一致。
    d2 = auth.update_session(
        s.token, s.csrf_token, 1,
        lambda sess: sess.profile.update({"role_hint": "owner"}),
    )
    log.info("request=update(valid v=1) allowed=%s detail=%s", d2.allowed, d2.detail)
    assert d2.allowed
    live2 = auth.get_active_session(s.token)
    assert live2.version == 2 and live2.profile == {"city": "Shanghai", "role_hint": "owner"}
