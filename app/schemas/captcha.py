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
