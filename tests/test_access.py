"""角色访问矩阵：越权必须拒绝并保留判定依据；结论不随顺序或并发改变。"""
import logging
from concurrent.futures import ThreadPoolExecutor

from app.access import can_read, can_write
from app.models import DenialReason, Resource, Role, Session

log = logging.getLogger("verify.access")


def make_session(user_id: str, role: Role) -> Session:
    return Session(
        session_id="s", user_id=user_id, role=role,
        token="t", csrf_token="c",
        expires_at=float("inf"), absolute_expires_at=float("inf"),
    )


PUBLIC = Resource("r-pub", owner_id="alice", visibility="public")
PRIVATE_ALICE = Resource("r-alice", owner_id="alice", visibility="private")

READ_MATRIX = [
    # (user, role, resource, expected_allowed, expected_reason)
    ("root", Role.ADMIN, PRIVATE_ALICE, True, None),
    ("alice", Role.OWNER, PRIVATE_ALICE, True, None),
    ("bob", Role.OWNER, PRIVATE_ALICE, False, DenialReason.NOT_OWNER),
    ("bob", Role.OWNER, PUBLIC, True, None),
    ("carol", Role.VIEWER, PUBLIC, True, None),
    ("carol", Role.VIEWER, PRIVATE_ALICE, False, DenialReason.FORBIDDEN_ROLE),
]

WRITE_MATRIX = [
    ("root", Role.ADMIN, PRIVATE_ALICE, True, None),
    ("alice", Role.OWNER, PRIVATE_ALICE, True, None),
    ("bob", Role.OWNER, PRIVATE_ALICE, False, DenialReason.NOT_OWNER),
    ("carol", Role.VIEWER, PUBLIC, False, DenialReason.FORBIDDEN_ROLE),
]


def test_read_matrix():
    for user, role, res, ok, reason in READ_MATRIX:
        d = can_read(make_session(user, role), res)
        log.info("request=read(user=%s role=%s res=%s) allowed=%s reason=%s detail=%s",
                 user, role.value, res.resource_id, d.allowed, d.reason, d.detail)
        assert d.allowed is ok and d.reason is reason


def test_write_matrix():
    for user, role, res, ok, reason in WRITE_MATRIX:
        d = can_write(make_session(user, role), res)
        log.info("request=write(user=%s role=%s res=%s) allowed=%s reason=%s detail=%s",
                 user, role.value, res.resource_id, d.allowed, d.reason, d.detail)
        assert d.allowed is ok and d.reason is reason


def test_decision_independent_of_order_and_concurrency():
    """并发与乱序下同一输入必须得到同一结论。"""
    cases = [(make_session(u, r), res) for u, r, res, _, _ in READ_MATRIX]
    sequential = [can_read(s, res) for s, res in cases]
    with ThreadPoolExecutor(max_workers=8) as pool:
        concurrent = list(pool.map(lambda c: can_read(*c), cases * 10))
    for i, d in enumerate(concurrent):
        base = sequential[i % len(cases)]
        assert (d.allowed, d.reason) == (base.allowed, base.reason)
    log.info("concurrent read decisions consistent across %d evaluations", len(concurrent))
