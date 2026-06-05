from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock

from app.core.enums import CaptchaType


@dataclass(frozen=True, slots=True)
class SliderAnswer:
    """服务端私有滑块答案，生产环境应写入 Redis 而不是下发给浏览器。"""

    target_x: int
    target_y: int
    piece_width: int
    piece_height: int
    shape: str


@dataclass(slots=True)
class CaptchaSession:
    captcha_token: str
    captcha_type: CaptchaType
    rsa_private_key_pem: str
    prompt: str
    width: int
    height: int
    slider_answer: SliderAnswer | None
    expires_at: datetime
    site_key: str | None = None
    action: str | None = None
    hostname: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at


@dataclass(slots=True)
class PrecheckSession:
    precheck_token: str
    rsa_private_key_pem: str
    expires_at: datetime
    site_key: str | None = None
    action: str | None = None
    hostname: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at


@dataclass(slots=True)
class VerifySignatureSession:
    verify_signature: str
    captcha_token: str
    risk_score: float
    expires_at: datetime
    site_key: str | None = None
    action: str | None = None
    hostname: str | None = None
    issued_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at


class InMemoryCaptchaSessionStore:
    """线程安全的内存 Mock 缓存。

    生产环境建议替换为 Redis。这里刻意把 captcha session、precheck key session 和
    verify signature 分成三类接口，方便后续把本类替换成 Redis 实现，而不影响 API 路由。
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._sessions: dict[str, CaptchaSession] = {}
        self._precheck_sessions: dict[str, PrecheckSession] = {}
        self._verify_signatures: dict[str, VerifySignatureSession] = {}

    def put(
        self,
        *,
        captcha_token: str,
        captcha_type: CaptchaType,
        rsa_private_key_pem: str,
        prompt: str,
        width: int,
        height: int,
        ttl_seconds: int,
        slider_answer: SliderAnswer | None = None,
        site_key: str | None = None,
        action: str | None = None,
        hostname: str | None = None,
    ) -> CaptchaSession:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        session = CaptchaSession(
            captcha_token=captcha_token,
            captcha_type=captcha_type,
            rsa_private_key_pem=rsa_private_key_pem,
            prompt=prompt,
            width=width,
            height=height,
            slider_answer=slider_answer,
            expires_at=expires_at,
            site_key=site_key,
            action=action,
            hostname=hostname,
        )
        with self._lock:
            self._sessions[captcha_token] = session
        return session

    def get(self, captcha_token: str) -> CaptchaSession | None:
        with self._lock:
            session = self._sessions.get(captcha_token)
            if session is None:
                return None
            if session.is_expired():
                self._sessions.pop(captcha_token, None)
                return None
            return session

    def delete(self, captcha_token: str) -> None:
        with self._lock:
            self._sessions.pop(captcha_token, None)

    def put_precheck(
        self,
        *,
        precheck_token: str,
        rsa_private_key_pem: str,
        ttl_seconds: int,
        site_key: str | None = None,
        action: str | None = None,
        hostname: str | None = None,
    ) -> PrecheckSession:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        session = PrecheckSession(
            precheck_token=precheck_token,
            rsa_private_key_pem=rsa_private_key_pem,
            expires_at=expires_at,
            site_key=site_key,
            action=action,
            hostname=hostname,
        )
        with self._lock:
            self._precheck_sessions[precheck_token] = session
        return session

    def consume_precheck(self, precheck_token: str) -> PrecheckSession | None:
        with self._lock:
            session = self._precheck_sessions.pop(precheck_token, None)
            if session is None:
                return None
            if session.is_expired():
                return None
            return session

    def put_verify_signature(
        self,
        *,
        verify_signature: str,
        captcha_token: str,
        risk_score: float,
        ttl_seconds: int,
        site_key: str | None = None,
        action: str | None = None,
        hostname: str | None = None,
    ) -> VerifySignatureSession:
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        session = VerifySignatureSession(
            verify_signature=verify_signature,
            captcha_token=captcha_token,
            risk_score=risk_score,
            expires_at=expires_at,
            site_key=site_key,
            action=action,
            hostname=hostname,
            issued_at=issued_at,
        )
        with self._lock:
            self._verify_signatures[verify_signature] = session
        return session

    def get_verify_signature(self, verify_signature: str) -> VerifySignatureSession | None:
        with self._lock:
            session = self._verify_signatures.get(verify_signature)
            if session is None:
                return None
            if session.is_expired():
                self._verify_signatures.pop(verify_signature, None)
                return None
            return session

    def consume_verify_signature(self, verify_signature: str) -> VerifySignatureSession | None:
        """一次性消费业务验签凭证。

        verify_signature 类似 Turnstile response token。业务后端调用 /api/siteverify
        成功或失败后都不应允许再次复用，因此这里直接 pop，天然防重放。
        """

        with self._lock:
            session = self._verify_signatures.pop(verify_signature, None)
            if session is None:
                return None
            if session.is_expired():
                return None
            return session

    def prune_expired(self) -> int:
        now = datetime.now(timezone.utc)
        with self._lock:
            expired_tokens = [
                token for token, session in self._sessions.items() if session.is_expired(now)
            ]
            for token in expired_tokens:
                self._sessions.pop(token, None)

            expired_prechecks = [
                token for token, session in self._precheck_sessions.items() if session.is_expired(now)
            ]
            for token in expired_prechecks:
                self._precheck_sessions.pop(token, None)

            expired_signatures = [
                signature
                for signature, session in self._verify_signatures.items()
                if session.is_expired(now)
            ]
            for signature in expired_signatures:
                self._verify_signatures.pop(signature, None)

            return len(expired_tokens) + len(expired_prechecks) + len(expired_signatures)


session_store = InMemoryCaptchaSessionStore()
