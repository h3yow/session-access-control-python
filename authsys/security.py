"""本地密码哈希工具。

仅用于演示与单测：使用固定方案的加盐 SHA-256，不依赖任何外部服务
或真实凭据。格式：``sha256$<salt>$<digest>``。
"""

from __future__ import annotations

import hashlib
import hmac
import os

_ALGO = "sha256"


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or os.urandom(16).hex()
    digest = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{_ALGO}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    if algo != _ALGO:
        return False
    candidate = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return hmac.compare_digest(candidate, digest)
