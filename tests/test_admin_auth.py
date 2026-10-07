"""账号管理操作（停用/改口令）的准入：必须是已登录的管理员，拒绝原因可区分。"""
import logging

from app.models import DenialReason
from tests.conftest import PASSWORDS, do_login

log = logging.getLogger("verify.admin")


def test_admin_authorization_decisions(auth, accounts):
    admin = do_login(auth, "root")
    owner = do_login(auth, "alice")
    viewer = do_login(auth, "carol")

    # 无凭据：会话级原因（401），与权限不够区分
    d, s = auth.authorize_admin(None)
    log.info("request=admin-op(token=None) reason=%s detail=%s", d.reason, d.detail)
    assert not d.allowed and d.reason is DenialReason.SESSION_NOT_FOUND and s is None

    # 不存在的凭据
    d, _ = auth.authorize_admin("never-issued")
    log.info("request=admin-op(token=unknown) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_NOT_FOUND

    # owner / viewer：凭据有效但能力不足 -> admin_required（403）
    for label, sess in (("owner", owner), ("viewer", viewer)):
        d, s = auth.authorize_admin(sess.token)
        log.info("request=admin-op(by %s) reason=%s detail=%s", label, d.reason, d.detail)
        assert not d.allowed and d.reason is DenialReason.ADMIN_REQUIRED and s is None

    # admin：通过
    d, s = auth.authorize_admin(admin.token)
    log.info("request=admin-op(by admin) allowed=%s detail=%s", d.allowed, d.detail)
    assert d.allowed and s is admin


def test_admin_authorization_rejects_invalidated_admin_session(auth, accounts):
    """管理员自己被停用/改密后，其会话同样过不了管理鉴权，且原因是账号失效而非权限。"""
    admin = do_login(auth, "root")
    accounts.set_enabled("root", False)
    d, _ = auth.authorize_admin(admin.token)
    log.info("request=admin-op(disabled admin) reason=%s", d.reason)
    assert d.reason is DenialReason.SESSION_INVALIDATED
    # 恢复
    accounts.set_enabled("root", True)


def test_admin_can_disable_and_change_password_through_service(auth, accounts):
    """端到端串联：鉴权通过后执行停用/改密确实生效。"""
    do_login(auth, "root")
    target = do_login(auth, "bob")
    token = target.token

    d = accounts.set_enabled("bob", False)
    assert d.allowed
    assert auth.validate(token).reason is DenialReason.SESSION_INVALIDATED

    accounts.set_enabled("bob", True)
    d = accounts.change_password("bob", "bob-rotated")
    assert d.allowed
    # 旧会话失效，旧口令登录被拒，新口令可登录
    assert auth.validate(token).reason is DenialReason.SESSION_INVALIDATED
    d, _ = auth.login("bob", PASSWORDS["bob"])
    log.info("request=login(bob old pw after admin change) reason=%s", d.reason)
    assert d.reason is DenialReason.PASSWORD_MISMATCH
    d, s = auth.login("bob", "bob-rotated")
    assert d.allowed and auth.validate(s.token).allowed
