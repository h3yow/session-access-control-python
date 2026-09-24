"""并发刷新：只有一个请求成功，其余被明确拒绝；任何时刻只有一个有效会话。"""

from __future__ import annotations

import threading

import pytest

from authsys.errors import AuthError, DenyReason


def test_concurrent_duplicate_refresh_single_winner(harness):
    session = harness.login("alice")
    token = session.token
    n = 32

    successes: list = []
    failures: list[DenyReason] = []
    barrier = threading.Barrier(n)
    lock = threading.Lock()

    def worker():
        barrier.wait()  # 尽可能同时发起
        try:
            r = harness.service.refresh(token)
            with lock:
                successes.append(r)
        except AuthError as exc:
            with lock:
                failures.append(exc.reason)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(
        f"input: {n} concurrent refresh(token={token[:8]}...) -> "
        f"success={len(successes)} failures={[f.value for f in failures]}",
    )
    assert len(successes) == 1
    assert len(failures) == n - 1
    # 失败者必须得到明确、可区分的原因，而不是静默并存
    assert set(failures) <= {DenyReason.SESSION_ROTATED, DenyReason.REFRESH_CONFLICT}
    assert set(failures), "其余刷新必须被明确拒绝"

    # 只有新 token 能通过认证，旧 token 确定为 ROTATED
    winner = successes[0]
    assert harness.service.authenticate(winner.new_token).version == 2
    with pytest.raises(AuthError) as exc:
        harness.service.authenticate(token)
    assert exc.value.reason is DenyReason.SESSION_ROTATED
    print(
        "basis: exactly one live token; old token=session_rotated; "
        f"losers={sorted({f.value for f in failures})}",
    )


def test_concurrent_refresh_with_optimistic_version(harness):
    """调用方都带相同的 expected_version：仍只有一个胜出，其余 version_conflict。"""
    session = harness.login("alice")
    token = session.token
    n = 16
    barrier = threading.Barrier(n)
    outcomes = {"ok": 0, DenyReason.REFRESH_CONFLICT.value: 0,
                DenyReason.SESSION_ROTATED.value: 0}
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            harness.service.refresh(token, expected_version=1)
            with lock:
                outcomes["ok"] += 1
        except AuthError as exc:
            with lock:
                outcomes[exc.reason.value] += 1

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"input: {n} refresh with expected_version=1 -> {outcomes}")
    assert outcomes["ok"] == 1
    assert outcomes[DenyReason.REFRESH_CONFLICT.value] + \
        outcomes[DenyReason.SESSION_ROTATED.value] == n - 1
