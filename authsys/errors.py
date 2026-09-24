"""可区分的拒绝原因定义。

认证 / 刷新 / 访问判定 / 会话写操作的所有失败结论，
都必须映射到这里的某个枚举值，保证调用方可以依据
``reason`` 做确定的分支处理。
"""

from __future__ import annotations

from enum import Enum


class DenyReason(str, Enum):
    # ---- 凭据认证阶段 ----
    INVALID_CREDENTIALS = "invalid_credentials"  # 用户名/密码错误

    # ---- 会话凭据校验阶段（三者必须可区分）----
    SESSION_NOT_FOUND = "session_not_found"      # 凭据不存在（含已被清理）
    SESSION_EXPIRED = "session_expired"          # 超过绝对/滑动有效期
    SESSION_REVOKED = "session_revoked"          # 被显式撤销（登出/管理员吊销）
    SESSION_ROTATED = "session_rotated"          # 已被刷新轮换，旧凭据立即失效

    # ---- 刷新阶段 ----
    REFRESH_CONFLICT = "refresh_conflict"        # 并发刷新：只有一个能成功

    # ---- 权限判定阶段 ----
    ACCESS_DENIED_ROLE = "access_denied_role"    # 角色不满足资源策略
    RESOURCE_NOT_FOUND = "resource_not_found"

    # ---- 会话写操作的保护校验（CSRF 风格）----
    PROOF_MISSING = "proof_missing"              # 缺少保护凭据
    PROOF_MISMATCH = "proof_mismatch"            # 保护凭据不匹配
    PROOF_EXPIRED = "proof_expired"              # 保护凭据随会话已过期/轮换
    VERSION_CONFLICT = "version_conflict"        # 乐观版本号不匹配，拒绝覆盖更新


class AuthError(Exception):
    """携带确定拒绝原因的异常。"""

    def __init__(self, reason: DenyReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")
