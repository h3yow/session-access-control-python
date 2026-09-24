"""会话写操作的保护校验与并发安全。"""

from __future__ import annotations

import threading

import pytest

from authsys.errors import AuthError, DenyReason


def test_write_requires_proof(harness):
    s = harness.login("alice")
    with pytest.raises(AuthError) as exc:
        harness.service.protected_write(s.token, None, s.version, lambda x: None)
    assert exc.value.reason is DenyReason.PROOF_MISSING
    print("input: write without proof -> reason=proof_missing")


def test_write_rejects_wrong_proof(harness):
    s = harness.login("alice")
    with pytest.raises(AuthError) as exc:
        harness.service.protected_write(s.token, "wrong-proof", s.version, lambda x: None)
    assert exc.value.reason is DenyReason.PROOF_MISMATCH
    print("input: write with wrong proof -> reason=proof_mismatch")


def test_write_rejects_rotated_proof(harness):
    s = harness.login("alice")
    first_generation_proof = s.proof
    r = harness.service.refresh(s.token)
    with pytest.raises(AuthError) as exc:
        harness.service.protected_write(
            r.new_token, first_generation_proof, r.version, lambda x: None,
        )
    assert exc.value.reason is DenyReason.PROOF_EXPIRED
    print("input: replay rotated proof -> reason=proof_expired")


def test_rejected_write_changes_nothing(harness):
    s = harness.login("alice")

    def boom(session):
        session.metadata["should-not-happen"] = "x"
        raise AssertionError("mutate must never run on a rejected request")

    with pytest.raises(AuthError):
        harness.service.protected_write(s.token, None, s.version, boom)

    untouched = harness.service.authenticate(s.token)
    assert untouched.version == s.version
    assert untouched.metadata == {}
    print("basis: rejected write -> mutate not invoked, version/metadata unchanged")


def test_successful_write_bumps_version(harness):
    s = harness.login("alice")
    w = harness.service.protected_write(
        s.token, s.proof, s.version,
        lambda sess: sess.metadata.update(color="blue"),
    )
    assert w.version == s.version + 1
    stored = harness.service.authenticate(s.token)
    assert stored.metadata == {"color": "blue"}
    print(f"input: valid proof+version -> new_version={w.version} metadata stored")


def test_stale_version_is_conflict_and_no_overwrite(harness):
    s = harness.login("alice")
    harness.service.protected_write(
        s.token, s.proof, 1, lambda sess: sess.metadata.update(a=1),
    )
    # 拿着旧版本号再次提交
    with pytest.raises(AuthError) as exc:
        harness.service.protected_write(
            s.token, s.proof, 1, lambda sess: sess.metadata.update(b=2),
        )
    assert exc.value.reason is DenyReason.VERSION_CONFLICT
    stored = harness.service.authenticate(s.token)
    assert stored.version == 2 and stored.metadata == {"a": 1}
    print("input: expected_version=1 actual=2 -> version_conflict, earlier write kept")


def test_concurrent_writes_no_lost_update(harness):
    """同一会话并发提交不同版本：恰好最新顺序全部串行生效，无更新被覆盖。"""
    s = harness.login("alice")

    # 先做 n-1 次串行演进，制造 n 个不同版本；然后用每个版本并发提交。
    n = 10
    tokens_per_version = {}
    cur_token, cur_proof, cur_version = s.token, s.proof, s.version
    for i in range(1, n):
        tokens_per_version[cur_version] = (cur_token, cur_proof)
        w = harness.service.protected_write(
            cur_token, cur_proof, cur_version,
            lambda sess, i=i: sess.metadata.update({f"k{i}": i}),
        )
        cur_version = w.version
    # 最终版本的有效凭据
    final = harness.service.authenticate(cur_token)
    assert final.version == n

    # 用全部过期版本并发重放：都应被 VERSION_CONFLICT 拒绝，不能回滚覆盖
    barrier = threading.Barrier(n - 1)
    rejected = []
    lock = threading.Lock()

    def worker(ver, tok, proof):
        barrier.wait()
        try:
            harness.service.protected_write(
                tok, proof, ver, lambda sess: sess.metadata.update(evil=True),
            )
        except AuthError as exc:
            with lock:
                rejected.append(exc.reason)

    threads = []
    for ver, (tok, proof) in tokens_per_version.items():
        threads.append(threading.Thread(target=worker, args=(ver, tok, proof)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(
        f"input: {n - 1} stale-version concurrent writes -> "
        f"reasons={sorted({r.value for r in rejected})}",
    )
    assert len(rejected) == n - 1
    assert set(rejected) == {DenyReason.VERSION_CONFLICT}
    final_after = harness.service.authenticate(cur_token)
    assert final_after.version == n
    assert "evil" not in final_after.metadata
    # 此前每次写入都保留
    assert final_after.metadata == {f"k{i}": i for i in range(1, n)}
    print(f"basis: all serial updates retained; no stale overwrite; version stays {n}")
