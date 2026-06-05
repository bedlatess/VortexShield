from typing import Any, Literal

from pydantic import BaseModel, Field

from app.core.enums import CaptchaType


class CaptchaDimensions(BaseModel):
    width: int = Field(..., examples=[320])
    height: int = Field(..., examples=[160])


class SliderPieceSize(BaseModel):
    width: int = Field(..., examples=[52])
    height: int = Field(..., examples=[52])


class CaptchaChallengeData(BaseModel):
    captcha_token: str = Field(..., examples=["sess_rsa_9f83a1b2c3d4e5f67890abcdef123456"])
    captcha_type: CaptchaType = Field(default=CaptchaType.SLIDER)
    bg_image: str = Field(..., description="Data URI of the slider background image.")
    slider_piece_b64: str = Field(..., description="Transparent PNG Data URI of the slider piece.")
    prompt: str = Field(..., examples=["拖动滑块，使拼图与缺口完全重合"])
    dimensions: CaptchaDimensions
    piece_size: SliderPieceSize
    initial_x: int = Field(default=0, description="Recommended initial x coordinate for the piece.")
    piece_y: int = Field(..., description="Vertical display coordinate for the slider piece.")
    rsa_public_key: str = Field(..., description="PEM encoded RSA-2048 public key.")


class CaptchaChallengeResponse(BaseModel):
    code: int = 200
    msg: str = "success"
    data: CaptchaChallengeData


class PrecheckKeyData(BaseModel):
    precheck_token: str
    rsa_public_key: str


class PrecheckKeyResponse(BaseModel):
    code: int = 200
    msg: str = "success"
    data: PrecheckKeyData


class CaptchaPrecheckRequest(BaseModel):
    precheck_token: str
    payload: str | dict[str, Any]
    site_key: str | None = Field(default=None, description="Public site key used by third-party pages.")
    action_name: str | None = Field(default=None, alias="action", description="Business action, e.g. login.")
    hostname: str | None = Field(default=None, description="Browser hostname collected by the SDK.")


class CheckboxChallengeData(BaseModel):
    captcha_token: str = Field(..., examples=["cbx_rsa_9f83a1b2c3d4e5f67890abcdef123456"])
    captcha_type: CaptchaType = Field(default=CaptchaType.CLICK_CHECKBOX)
    prompt: str = Field(default="请点击复选框完成安全确认")
    rsa_public_key: str = Field(..., description="PEM encoded RSA-2048 public key.")


class CaptchaPrecheckData(BaseModel):
    action: Literal["pass", "challenge"]
    captcha_type: CaptchaType
    verify_signature: str | None = None
    expires_in: int | None = None
    risk_score: float
    reason: str
    challenge: CaptchaChallengeData | CheckboxChallengeData | None = None
    features: dict[str, Any] | None = None


class CaptchaPrecheckResponse(BaseModel):
    code: int
    msg: str
    data: CaptchaPrecheckData


class CaptchaVerifyRequest(BaseModel):
    captcha_token: str
    payload: str | dict[str, Any]
    site_key: str | None = Field(default=None, description="Public site key used by third-party pages.")
    action_name: str | None = Field(default=None, alias="action", description="Business action, e.g. login.")
    hostname: str | None = Field(default=None, description="Browser hostname collected by the SDK.")


class CaptchaVerifyData(BaseModel):
    verify_signature: str | None = None
    expires_in: int | None = None
    risk_score: float | None = None
    reason: str | None = None
    features: dict[str, Any] | None = None


class CaptchaVerifyResponse(BaseModel):
    code: int
    msg: str
    data: CaptchaVerifyData


class SiteVerifyRequest(BaseModel):
    secret: str = Field(..., description="Private site secret. Must only be used by the business backend.")
    response: str = Field(..., description="verify_signature returned by the browser SDK.")
    remoteip: str | None = Field(default=None, description="Optional end-user IP address.")
    action_name: str | None = Field(default=None, alias="action", description="Expected business action.")
    hostname: str | None = Field(default=None, description="Expected hostname.")


class SiteVerifyResponse(BaseModel):
    success: bool
    score: float | None = None
    action: str | None = None
    hostname: str | None = None
    challenge_ts: str | None = None
    error_codes: list[str] = Field(default_factory=list)


class SiteAdminCreateRequest(BaseModel):
    allowed_domains: list[str] = Field(..., min_length=1, description="Domains that may use this site key.")
    allowed_actions: list[str] = Field(default_factory=lambda: ["login"], description="Allowed business actions.")
    admin_token: str = Field(..., min_length=1, description="Admin console token.")


class SiteAdminData(BaseModel):
    site_key: str
    allowed_domains: list[str]
    allowed_actions: list[str]
    enabled: bool
    created_at: str


class SiteAdminCreateData(SiteAdminData):
    secret: str = Field(..., description="Private secret returned once at creation time.")


class SiteAdminListResponse(BaseModel):
    code: int = 200
    msg: str = "success"
    data: list[SiteAdminData]


class SiteAdminCreateResponse(BaseModel):
    code: int = 200
    msg: str = "success"
    data: SiteAdminCreateData | None = None
