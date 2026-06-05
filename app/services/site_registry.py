from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from urllib.parse import urlparse

from app.core.config import get_settings


DEFAULT_DEMO_SITE_KEY = "vsec_site_demo"
DEFAULT_DEMO_SECRET = "vsec_secret_demo"
DEFAULT_DEMO_ACTION = "login"
DEFAULT_DEMO_HOSTNAME = "localhost"


@dataclass(frozen=True, slots=True)
class SiteConfig:
    """第三方站点接入配置。

    真实生产环境建议把这份配置放入数据库或配置中心，并提供控制台给站点管理员
    自助创建 site_key / secret。MVP 阶段使用内存注册表，但仍然只保存 secret_hash，
    避免把业务后端密钥以明文形式散落在进程内。
    """

    site_key: str
    secret_hash: str
    allowed_domains: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    enabled: bool = True
    created_at: str = ""


@dataclass(frozen=True, slots=True)
class SiteValidationResult:
    ok: bool
    reason: str
    site: SiteConfig | None = None
    normalized_hostname: str = ""
    normalized_action: str = ""


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class InMemorySiteRegistry:
    """轻量站点注册表，用来模拟 Cloudflare Turnstile 的 siteKey/secret 模型。

    站点配置会同步写入本地 JSON 文件，解决控制台创建 API 后服务重启丢失的问题。
    生产集群建议替换为数据库或集中式配置服务，避免多实例写文件带来的同步边界。
    """

    def __init__(self, storage_path: str | os.PathLike[str] | None = None) -> None:
        demo_site = SiteConfig(
            site_key=DEFAULT_DEMO_SITE_KEY,
            secret_hash=hash_secret(DEFAULT_DEMO_SECRET),
            allowed_domains=(
                "localhost",
                "127.0.0.1",
                "vsec.pawn.eu.org",
                "pawn.eu.org",
            ),
            allowed_actions=("default", "login", "signup", "checkout"),
            enabled=True,
            created_at=_utc_now(),
        )
        self._lock = RLock()
        self._storage_path = Path(storage_path or get_settings().site_registry_path)
        self._sites: dict[str, SiteConfig] = {demo_site.site_key: demo_site}
        self._load_from_disk()

    def get_site(self, site_key: str) -> SiteConfig | None:
        with self._lock:
            return self._sites.get(str(site_key or "").strip())

    def find_by_secret(self, secret: str) -> SiteConfig | None:
        secret_hash = hash_secret(str(secret or ""))
        with self._lock:
            for site in self._sites.values():
                if secrets.compare_digest(site.secret_hash, secret_hash):
                    return site
        return None

    def list_sites(self) -> list[SiteConfig]:
        with self._lock:
            return sorted(self._sites.values(), key=lambda site: site.created_at, reverse=True)

    def create_site(
        self,
        *,
        allowed_domains: list[str],
        allowed_actions: list[str],
    ) -> tuple[SiteConfig, str]:
        normalized_domains = tuple(
            dict.fromkeys(
                hostname
                for hostname in (normalize_hostname(domain) for domain in allowed_domains)
                if hostname
            )
        )
        normalized_actions = tuple(
            dict.fromkeys(
                action
                for action in (normalize_action(action) for action in allowed_actions)
                if action
            )
        )
        if not normalized_domains:
            raise ValueError("allowed_domains_required")
        if not normalized_actions:
            raise ValueError("allowed_actions_required")

        for _attempt in range(8):
            site_key = f"vsec_site_{secrets.token_urlsafe(18).replace('-', '').replace('_', '')[:24]}"
            secret = f"vsec_secret_{secrets.token_urlsafe(32)}"
            site = SiteConfig(
                site_key=site_key,
                secret_hash=hash_secret(secret),
                allowed_domains=normalized_domains,
                allowed_actions=normalized_actions,
                enabled=True,
                created_at=_utc_now(),
            )
            with self._lock:
                if site_key not in self._sites:
                    self._sites[site_key] = site
                    self._persist_locked()
                    return site, secret
        raise RuntimeError("site_key_generation_failed")

    def set_enabled(self, site_key: str, enabled: bool) -> SiteConfig | None:
        normalized_key = str(site_key or "").strip()
        with self._lock:
            site = self._sites.get(normalized_key)
            if site is None:
                return None
            updated = replace(site, enabled=enabled)
            self._sites[normalized_key] = updated
            self._persist_locked()
            return updated

    def delete_site(self, site_key: str) -> SiteConfig | None:
        normalized_key = str(site_key or "").strip()
        # 演示站点用于本地联调和线上探针，禁止在管理面板中删除，避免一键接入样例失效。
        if normalized_key == DEFAULT_DEMO_SITE_KEY:
            raise ValueError("demo_site_cannot_be_deleted")
        with self._lock:
            site = self._sites.pop(normalized_key, None)
            if site is not None:
                self._persist_locked()
            return site

    def rotate_secret(self, site_key: str) -> tuple[SiteConfig, str] | None:
        normalized_key = str(site_key or "").strip()
        with self._lock:
            site = self._sites.get(normalized_key)
            if site is None:
                return None
            secret = f"vsec_secret_{secrets.token_urlsafe(32)}"
            updated = replace(site, secret_hash=hash_secret(secret))
            self._sites[normalized_key] = updated
            self._persist_locked()
            return updated, secret

    def validate_site_context(
        self,
        *,
        site_key: str,
        action: str | None,
        hostname: str | None,
    ) -> SiteValidationResult:
        normalized_hostname = normalize_hostname(hostname)
        normalized_action = normalize_action(action)
        site = self.get_site(site_key)

        if site is None:
            return SiteValidationResult(
                ok=False,
                reason="invalid_site_key",
                normalized_hostname=normalized_hostname,
                normalized_action=normalized_action,
            )
        if not site.enabled:
            return SiteValidationResult(
                ok=False,
                reason="site_disabled",
                site=site,
                normalized_hostname=normalized_hostname,
                normalized_action=normalized_action,
            )
        if normalized_action not in site.allowed_actions:
            return SiteValidationResult(
                ok=False,
                reason="action_not_allowed",
                site=site,
                normalized_hostname=normalized_hostname,
                normalized_action=normalized_action,
            )
        if normalized_hostname not in site.allowed_domains:
            return SiteValidationResult(
                ok=False,
                reason="hostname_not_allowed",
                site=site,
                normalized_hostname=normalized_hostname,
                normalized_action=normalized_action,
            )
        return SiteValidationResult(
            ok=True,
            reason="ok",
            site=site,
            normalized_hostname=normalized_hostname,
            normalized_action=normalized_action,
        )

    def _load_from_disk(self) -> None:
        if not self._storage_path.exists():
            return
        try:
            raw = json.loads(self._storage_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return

        loaded: dict[str, SiteConfig] = {}
        for item in raw:
            site = _site_from_json(item)
            if site is not None:
                loaded[site.site_key] = site
        if loaded:
            self._sites.update(loaded)

    def _persist_locked(self) -> None:
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        serializable = [
            _site_to_json(site)
            for site in sorted(self._sites.values(), key=lambda site: site.created_at, reverse=True)
        ]
        payload = json.dumps(serializable, ensure_ascii=False, indent=2)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(self._storage_path.parent),
            delete=False,
        ) as temp_file:
            temp_file.write(payload)
            temp_name = temp_file.name
        os.replace(temp_name, self._storage_path)


def normalize_action(action: str | None) -> str:
    normalized = str(action or DEFAULT_DEMO_ACTION).strip().lower()
    return normalized or DEFAULT_DEMO_ACTION


def normalize_hostname(hostname: str | None) -> str:
    raw = str(hostname or DEFAULT_DEMO_HOSTNAME).strip().lower()
    if not raw:
        return DEFAULT_DEMO_HOSTNAME

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0]
    host = host.strip("[]").rstrip(".")
    return host or DEFAULT_DEMO_HOSTNAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _site_to_json(site: SiteConfig) -> dict[str, object]:
    data = asdict(site)
    data["allowed_domains"] = list(site.allowed_domains)
    data["allowed_actions"] = list(site.allowed_actions)
    return data


def _site_from_json(value: object) -> SiteConfig | None:
    if not isinstance(value, dict):
        return None
    try:
        site_key = str(value["site_key"]).strip()
        secret_hash = str(value["secret_hash"]).strip()
        allowed_domains = tuple(str(item).strip() for item in value["allowed_domains"] if str(item).strip())
        allowed_actions = tuple(str(item).strip() for item in value["allowed_actions"] if str(item).strip())
        enabled = bool(value.get("enabled", True))
        created_at = str(value.get("created_at") or _utc_now())
    except (KeyError, TypeError):
        return None
    if not site_key or not secret_hash or not allowed_domains or not allowed_actions:
        return None
    return SiteConfig(
        site_key=site_key,
        secret_hash=secret_hash,
        allowed_domains=allowed_domains,
        allowed_actions=allowed_actions,
        enabled=enabled,
        created_at=created_at,
    )


site_registry = InMemorySiteRegistry()
