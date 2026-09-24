import logging

import pytest

from app.auth import AuthService


class FakeClock:
    """可手动推进的时钟，用于确定性地构造过期场景。"""

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
def auth(clock) -> AuthService:
    return AuthService(ttl_seconds=60.0, clock=clock)


@pytest.fixture
def log():
    logger = logging.getLogger("verify")
    return logger
