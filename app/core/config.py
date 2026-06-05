import os
from functools import lru_cache

from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Runtime settings for the captcha service."""

    app_name: str = "VortexShield"
    captcha_width: int = Field(default=320, ge=200, le=640)
    captcha_height: int = Field(default=160, ge=100, le=360)
    challenge_ttl_seconds: int = Field(default=180, ge=30, le=900)
    verify_signature_ttl_seconds: int = Field(default=60, ge=10, le=300)
    slider_x_tolerance_px: float = Field(default=8.0, ge=0.0, le=20.0)
    admin_console_token: str = Field(
        default_factory=lambda: os.getenv("VSEC_ADMIN_TOKEN", "vsec_admin_demo"),
        description="Token required by the visual API console to create/list site keys.",
    )
    site_registry_path: str = Field(
        default_factory=lambda: os.getenv("VSEC_SITE_REGISTRY_PATH", "data/site_registry.json"),
        description="JSON file used by the demo siteKey registry. Use DB/Redis in clustered production.",
    )

    # Phase 2/3 使用 32 字节密钥，对应 AES-GCM-256。
    aes_key_bytes: int = 32


@lru_cache
def get_settings() -> Settings:
    return Settings()
