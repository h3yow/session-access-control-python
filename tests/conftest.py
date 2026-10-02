import logging

import pytest

from app.accounts import AccountStore
from app.auth import AuthService
from app.models import Role


class FakeClock:
    """可手动推进的时钟，用于确定性地构造过期/锁定/上限场景。"""

    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def accounts() -> AccountStore:
    """测试用本地账号：含 admin/owner/viewer 各一、一个停用账号 dave。"""
    return AccountStore.with_passwords(
        [
            ("root", "root-pw", Role.ADMIN, True),
            ("alice", "alice-pw", Role.OWNER, True),
            ("bob", "bob-pw", Role.OWNER, True),
            ("carol", "carol-pw", Role.VIEWER, True),
            ("dave", "dave-pw", Role.VIEWER, False),
        ]
    )


@pytest.fixture
def auth(clock, accounts) -> AuthService:
    # TTL=60s；总时长上限=200s；连续失败 5 次锁定 60s。
    return AuthService(
        accounts=accounts,
        ttl_seconds=60.0,
        max_session_seconds=200.0,
        max_login_failures=5,
        lockout_seconds=60.0,
        clock=clock,
    )


@pytest.fixture
def log():
    logger = logging.getLogger("verify")
    return logger
