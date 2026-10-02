import logging

import pytest

from app.accounts import AccountStore
from app.auth import AuthService
from app.models import Role

# 测试专用假口令，仅用于本地验证。
PASSWORDS = {
    "alice": "alice-pw",
    "bob": "bob-pw",
    "carol": "carol-pw",
    "root": "root-pw",
    "dave": "dave-pw",
}


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
def accounts(clock) -> AccountStore:
    """本地账号仓库：3 次连续失败锁定 30s；dave 为预置停用账号。"""
    store = AccountStore(max_failures=3, lockout_seconds=30.0, clock=clock)
    store.add_account("alice", PASSWORDS["alice"], Role.OWNER)
    store.add_account("bob", PASSWORDS["bob"], Role.OWNER)
    store.add_account("carol", PASSWORDS["carol"], Role.VIEWER)
    store.add_account("root", PASSWORDS["root"], Role.ADMIN)
    store.add_account("dave", PASSWORDS["dave"], Role.VIEWER, enabled=False)
    return store


@pytest.fixture
def auth(accounts, clock) -> AuthService:
    # ttl 60s，续期总时长上限 120s（自登录时刻起）。
    return AuthService(accounts, ttl_seconds=60.0, max_lifetime_seconds=120.0, clock=clock)


def do_login(auth: AuthService, username: str = "alice"):
    """以正确口令登录并断言成功，返回会话。"""
    decision, session = auth.login(username, PASSWORDS[username])
    assert decision.allowed, f"登录应成功: {decision.detail}"
    return session


@pytest.fixture
def log():
    logger = logging.getLogger("verify")
    return logger
