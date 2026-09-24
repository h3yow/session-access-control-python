"""pytest 公共夹具：纯内存的本地环境，无任何外部服务/真实凭据依赖。"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

import pytest

from authsys.access import AccessControl
from authsys.models import Resource, Role, User
from authsys.security import hash_password
from authsys.service import AuthService
from authsys.store import SessionStore


@dataclass
class Harness:
    store: SessionStore
    service: AuthService
    access: AccessControl
    alice: User
    bob: User
    root: User
    guest: User
    doc: Resource

    def login(self, name: str, password: str = "pw123"):
        return self.service.login(name, password)


def _build_harness(ttl: float = 900.0, absolute_ttl: float = 8 * 3600.0) -> Harness:
    store = SessionStore()
    service = AuthService(store, ttl_seconds=ttl, absolute_ttl_seconds=absolute_ttl)
    access = AccessControl(service)

    alice = User("u-alice", "alice", hash_password("pw123"), frozenset({Role.USER}))
    bob = User("u-bob", "bob", hash_password("pw123"), frozenset({Role.USER}))
    root = User("u-root", "root", hash_password("pw123"), frozenset({Role.ADMIN}))
    guest = User("u-guest", "guest", hash_password("pw123"), frozenset({Role.GUEST}))
    for u in (alice, bob, root, guest):
        access.add_user(u)

    # 默认资源：read=[admin,owner,user]，write/delete=[admin,owner]
    doc = Resource("doc-1", owner_id="u-alice")
    access.add_resource(doc)
    # 一个仅管理员可写、且连普通用户都不可读的受限资源
    secret = Resource(
        "secret-1", owner_id="u-root",
        read_roles=frozenset({Role.ADMIN, Role.OWNER}),
        write_roles=frozenset({Role.ADMIN, Role.OWNER}),
        delete_roles=frozenset({Role.ADMIN}),
    )
    access.add_resource(secret)

    return Harness(store, service, access, alice, bob, root, guest, doc)


@pytest.fixture
def harness() -> Harness:
    return _build_harness()


@pytest.fixture(autouse=True)
def _test_logging(caplog):
    """让单测日志打印“请求输入 + 判定依据”。

    caplog 负责捕获断言，StreamHandler 保证日志实时打印到控制台。
    """
    logger = logging.getLogger("authsys")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"),
    )
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger="authsys"):
        yield
    logger.removeHandler(handler)
