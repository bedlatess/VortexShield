from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque
from typing import Any, Deque

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.enums import CaptchaType, RiskLevel
from app.schemas.captcha import (
    CaptchaChallengeData,
    CaptchaChallengeResponse,
    CaptchaDimensions,
    CaptchaPrecheckData,
    CaptchaPrecheckRequest,
    CaptchaPrecheckResponse,
    CaptchaVerifyData,
    CaptchaVerifyRequest,
    CaptchaVerifyResponse,
    CheckboxChallengeData,
    PrecheckKeyData,
    PrecheckKeyResponse,
    SliderPieceSize,
)
from app.services.captcha_generator import generate_slider_challenge
from app.services.crypto import PayloadDecryptError, decrypt_hybrid_payload, generate_rsa_key_pair
from app.services.data_logger import log_trajectory_event_async
from app.services.risk_engine import evaluate_environment, extract_trajectory_features
from app.services.session_store import SliderAnswer, session_store


router = APIRouter()
settings = get_settings()

PIECE_WIDTH = 53.0
STANDARD_OVERLAP_RATIO = 0.85
HUMAN_FRIENDLY_OVERLAP_RATIO = 0.70
HIGH_RISK_SCORE_THRESHOLD = 0.70
LOW_RISK_SCORE_THRESHOLD = 0.30
VERIFY_RATE_LIMIT = 15
VERIFY_RATE_WINDOW_SECONDS = 60.0
_verify_rate_buckets: dict[str, Deque[float]] = defaultdict(deque)


@router.get("/precheck-key", response_model=PrecheckKeyResponse)
def create_precheck_key() -> PrecheckKeyResponse:
    """下发静默预检 RSA 公钥。

    公钥只用于加密 fingerprint；私钥短时保存在 precheck session 中，并在 /precheck
    消费后立即删除，降低重放和密钥复用风险。
    """

    rsa_private_key_pem, rsa_public_key_pem = generate_rsa_key_pair()
    precheck_token = f"pre_rsa_{secrets.token_hex(16)}"
    session_store.put_precheck(
        precheck_token=precheck_token,
        rsa_private_key_pem=rsa_private_key_pem,
        ttl_seconds=settings.challenge_ttl_seconds,
    )
    session_store.prune_expired()
    return PrecheckKeyResponse(
        data=PrecheckKeyData(
            precheck_token=precheck_token,
            rsa_public_key=rsa_public_key_pem,
        )
    )


@router.post("/precheck", response_model=CaptchaPrecheckResponse)
def precheck_captcha(request: CaptchaPrecheckRequest) -> CaptchaPrecheckResponse:
    """Turnstile 风格中控预检。

    - RiskLevel.LOW -> CaptchaType.SILENT：直接签发 verify_signature。
    - RiskLevel.MEDIUM -> CaptchaType.CLICK_CHECKBOX：返回轻交互复选框类型。
    - RiskLevel.HIGH -> CaptchaType.SLIDER：返回滑块拼图挑战。
    """

    precheck_session = session_store.consume_precheck(request.precheck_token)
    if precheck_session is None:
        return _precheck_failed("precheck_expired_or_not_found")

    try:
        plaintext = decrypt_hybrid_payload(request.payload, precheck_session.rsa_private_key_pem)
    except PayloadDecryptError:
        return _precheck_failed("precheck_payload_decrypt_failed")

    fingerprint = plaintext.get("fingerprint")
    if not isinstance(fingerprint, dict):
        return _precheck_failed("malformed_fingerprint")

    env_result = evaluate_environment(fingerprint)
    risk_level = env_result["risk_level"]
    risk_score = float(env_result["score"])
    reason = str(env_result["reason"])
    features = env_result.get("features")

    if risk_level == RiskLevel.LOW:
        verify_signature = _issue_verify_signature(
            captcha_token=f"precheck:{request.precheck_token}",
            risk_score=risk_score,
        )
        return CaptchaPrecheckResponse(
            code=200,
            msg="success",
            data=CaptchaPrecheckData(
                action="pass",
                captcha_type=CaptchaType.SILENT,
                verify_signature=verify_signature,
                expires_in=settings.verify_signature_ttl_seconds,
                risk_score=risk_score,
                reason=reason,
                challenge=None,
                features=features,
            ),
        )

    if risk_level == RiskLevel.MEDIUM:
        checkbox_data = _create_checkbox_challenge_data()
        return CaptchaPrecheckResponse(
            code=200,
            msg="checkbox_required",
            data=CaptchaPrecheckData(
                action="challenge",
                captcha_type=CaptchaType.CLICK_CHECKBOX,
                verify_signature=None,
                expires_in=None,
                risk_score=risk_score,
                reason=reason,
                challenge=checkbox_data,
                features=features,
            ),
        )

    challenge_data = _create_slider_challenge_data()
    return CaptchaPrecheckResponse(
        code=200,
        msg="slider_required",
        data=CaptchaPrecheckData(
            action="challenge",
            captcha_type=CaptchaType.SLIDER,
            verify_signature=None,
            expires_in=None,
            risk_score=risk_score,
            reason=reason,
            challenge=challenge_data,
            features=features,
        ),
    )


@router.get("/challenge", response_model=CaptchaChallengeResponse)
def create_captcha_challenge() -> CaptchaChallengeResponse:
    """显式创建滑块挑战，主要用于本地调试和高风险降级路径。"""

    return CaptchaChallengeResponse(data=_create_slider_challenge_data())


@router.post("/verify", response_model=CaptchaVerifyResponse)
def verify_captcha(
    payload: CaptchaVerifyRequest,
    request: Request,
) -> CaptchaVerifyResponse | JSONResponse:
    """校验 step-up challenge。

    Phase 6 已废弃旧版“四字符点选顺序”方案。本接口现在只接受滑块类 payload：
    {
        "captcha_token": "...",
        "slider_x": 132.5,
        "tracks": [[x, y, t, event_type], ...],
        "fingerprint": {...}
    }
    """

    client_ip = _get_client_ip(request)
    if not _allow_verify_request(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "code": 429,
                "msg": "too_many_requests",
                "data": {
                    "verify_signature": None,
                    "expires_in": None,
                    "risk_score": 1.0,
                    "reason": "rate_limited",
                    "features": {"client_ip": client_ip, "limit_per_minute": VERIFY_RATE_LIMIT},
                },
            },
        )

    session = session_store.get(payload.captcha_token)
    if session is None:
        return _verify_failed_with_log(
            "challenge_expired_or_not_found",
            captcha_type=None,
            plaintext=None,
        )

    try:
        plaintext = decrypt_hybrid_payload(payload.payload, session.rsa_private_key_pem)
    except PayloadDecryptError:
        return _verify_failed_with_log(
            "payload_decrypt_failed",
            captcha_type=session.captcha_type,
            plaintext=None,
        )

    if plaintext.get("captcha_token") != payload.captcha_token:
        return _verify_failed_with_log(
            "payload_token_mismatch",
            captcha_type=session.captcha_type,
            plaintext=plaintext,
        )

    captcha_type_result = _parse_payload_captcha_type(plaintext)
    if not captcha_type_result["ok"]:
        return _verify_failed_with_log(
            captcha_type_result["reason"],
            captcha_type=session.captcha_type,
            plaintext=plaintext,
        )

    captcha_type = captcha_type_result["captcha_type"]
    if session.captcha_type != captcha_type:
        return _verify_failed_with_log(
            "captcha_type_mismatch",
            captcha_type=captcha_type,
            plaintext=plaintext,
            features={"payload_type": captcha_type, "session_type": session.captcha_type},
        )

    if captcha_type == CaptchaType.SILENT:
        return _verify_silent_challenge(payload.captcha_token)

    if captcha_type == CaptchaType.CLICK_CHECKBOX:
        return _verify_checkbox_challenge(payload.captcha_token, plaintext, captcha_type)

    if captcha_type != CaptchaType.SLIDER or session.slider_answer is None:
        return _verify_failed_with_log(
            "unsupported_captcha_type",
            captcha_type=captcha_type,
            plaintext=plaintext,
        )

    position_result = _calculate_slider_overlap(plaintext, session.slider_answer)
    if not position_result["ok"]:
        return _verify_failed_with_log(
            position_result["reason"],
            captcha_type=captcha_type,
            plaintext=plaintext,
            features=position_result.get("features"),
        )

    risk_result = _evaluate_tracks_or_fail(
        plaintext,
        bot_score_threshold=HIGH_RISK_SCORE_THRESHOLD,
    )
    if not risk_result["ok"]:
        features = _merge_features(
            risk_result.get("features"),
            position_result.get("features"),
        )
        return _verify_failed_with_log(
            risk_result["reason"],
            captcha_type=captcha_type,
            plaintext=plaintext,
            risk_score=risk_result.get("risk_score"),
            features=features,
            overlap_ratio=position_result.get("overlap_ratio"),
        )

    dynamic_result = _decide_slider_dynamic_tolerance(
        position_result=position_result,
        risk_score=float(risk_result["risk_score"]),
        risk_features=risk_result.get("features"),
    )
    if not dynamic_result["ok"]:
        return _verify_failed_with_log(
            dynamic_result["reason"],
            captcha_type=captcha_type,
            plaintext=plaintext,
            risk_score=float(risk_result["risk_score"]),
            features=dynamic_result.get("features"),
            overlap_ratio=position_result.get("overlap_ratio"),
        )

    verify_signature = _issue_verify_signature(
        captcha_token=payload.captcha_token,
        risk_score=float(risk_result["risk_score"]),
    )
    session_store.delete(payload.captcha_token)
    session_store.prune_expired()

    return _verify_success_response(
        verify_signature=verify_signature,
        risk_score=float(risk_result["risk_score"]),
        features=dynamic_result.get("features"),
        captcha_type=captcha_type,
        plaintext=plaintext,
        overlap_ratio=position_result.get("overlap_ratio"),
    )


def _verify_silent_challenge(captcha_token: str) -> CaptchaVerifyResponse:
    """SILENT 二次确认/续签。

    能拿到 SILENT token 的请求已经在 precheck 阶段被评估为低风险；这里仅签发短时
    verify_signature 并销毁当前 token，避免重复使用。
    """

    verify_signature = _issue_verify_signature(captcha_token=captcha_token, risk_score=0.05)
    session_store.delete(captcha_token)
    session_store.prune_expired()
    return _verify_success_response(
        verify_signature=verify_signature,
        risk_score=0.05,
        features={"captcha_type": CaptchaType.SILENT},
        captcha_type=CaptchaType.SILENT,
        plaintext=None,
    )


def _create_checkbox_challenge_data() -> CheckboxChallengeData:
    rsa_private_key_pem, rsa_public_key_pem = generate_rsa_key_pair()
    captcha_token = f"cbx_rsa_{secrets.token_hex(16)}"
    prompt = "请点击复选框完成安全确认"

    session_store.put(
        captcha_token=captcha_token,
        captcha_type=CaptchaType.CLICK_CHECKBOX,
        rsa_private_key_pem=rsa_private_key_pem,
        prompt=prompt,
        width=320,
        height=72,
        slider_answer=None,
        ttl_seconds=settings.challenge_ttl_seconds,
    )
    session_store.prune_expired()

    return CheckboxChallengeData(
        captcha_token=captcha_token,
        captcha_type=CaptchaType.CLICK_CHECKBOX,
        prompt=prompt,
        rsa_public_key=rsa_public_key_pem,
    )


def _create_slider_challenge_data() -> CaptchaChallengeData:
    challenge = generate_slider_challenge(
        width=settings.captcha_width,
        height=settings.captcha_height,
    )
    rsa_private_key_pem, rsa_public_key_pem = generate_rsa_key_pair()
    captcha_token = f"sess_rsa_{secrets.token_hex(16)}"
    prompt = "拖动滑块，使拼图与缺口完全重合"

    session_store.put(
        captcha_token=captcha_token,
        captcha_type=CaptchaType.SLIDER,
        rsa_private_key_pem=rsa_private_key_pem,
        prompt=prompt,
        width=challenge.width,
        height=challenge.height,
        slider_answer=SliderAnswer(
            target_x=challenge.target_x,
            target_y=challenge.target_y,
            piece_width=challenge.piece_width,
            piece_height=challenge.piece_height,
            shape=challenge.shape,
        ),
        ttl_seconds=settings.challenge_ttl_seconds,
    )
    session_store.prune_expired()

    return CaptchaChallengeData(
        captcha_token=captcha_token,
        captcha_type=CaptchaType.SLIDER,
        bg_image=challenge.bg_image,
        slider_piece_b64=challenge.slider_piece_b64,
        prompt=prompt,
        dimensions=CaptchaDimensions(width=challenge.width, height=challenge.height),
        piece_size=SliderPieceSize(width=challenge.piece_width, height=challenge.piece_height),
        initial_x=0,
        piece_y=challenge.target_y,
        rsa_public_key=rsa_public_key_pem,
    )


def _verify_checkbox_challenge(
    captcha_token: str,
    plaintext: dict[str, Any],
    captcha_type: CaptchaType,
) -> CaptchaVerifyResponse:
    """校验轻交互复选框挑战。

    复选框不做空间答案校验，但仍要求：
    - payload 经过当前 session 的 RSA+AES 混合加密链路；
    - 用户确实提交 checkbox_checked=true；
    - hover/click 轨迹存在，时间戳和环境指纹可被风控引擎检查。
    """

    if plaintext.get("checkbox_checked") is not True:
        return _verify_failed_with_log(
            "checkbox_not_checked",
            captcha_type=captcha_type,
            plaintext=plaintext,
        )

    risk_result = _evaluate_tracks_or_fail(plaintext)
    if not risk_result["ok"]:
        return _verify_failed_with_log(
            risk_result["reason"],
            captcha_type=captcha_type,
            plaintext=plaintext,
            risk_score=risk_result.get("risk_score"),
            features=risk_result.get("features"),
        )

    verify_signature = _issue_verify_signature(
        captcha_token=captcha_token,
        risk_score=float(risk_result["risk_score"]),
    )
    session_store.delete(captcha_token)
    session_store.prune_expired()
    return _verify_success_response(
        verify_signature=verify_signature,
        risk_score=float(risk_result["risk_score"]),
        features=risk_result.get("features"),
        captcha_type=captcha_type,
        plaintext=plaintext,
    )


def _calculate_slider_overlap(plaintext: dict[str, Any], answer: SliderAnswer) -> dict[str, Any]:
    """计算滑块与真实缺口的面积重合率。

    旧逻辑使用 abs(slider_x - target_x) <= tolerance，体验上接近“像素级卡尺”。
    新逻辑改为面积重合率：
        overlap_ratio = max(0, 1 - abs(slider_x - target_x) / PIECE_WIDTH)

    这里只负责产生判定指标，不直接按坐标拒绝。最终是否放行要结合轨迹风险分值，
    由 _decide_slider_dynamic_tolerance 统一决策。
    """

    try:
        slider_x = float(plaintext["slider_x"])
    except (KeyError, TypeError, ValueError) as exc:
        return {"ok": False, "reason": "malformed_slider_x", "features": {"error": str(exc)}}

    delta = abs(slider_x - float(answer.target_x))
    overlap_ratio = max(0.0, 1.0 - delta / PIECE_WIDTH)
    features = {
        "actual_x": round(slider_x, 3),
        "target_x": answer.target_x,
        "delta": round(delta, 3),
        "piece_width": PIECE_WIDTH,
        "overlap_ratio": round(overlap_ratio, 6),
        "standard_overlap_required": STANDARD_OVERLAP_RATIO,
        "human_friendly_overlap_required": HUMAN_FRIENDLY_OVERLAP_RATIO,
    }
    return {
        "ok": True,
        "reason": "overlap_calculated",
        "overlap_ratio": overlap_ratio,
        "features": features,
    }


def _decide_slider_dynamic_tolerance(
    *,
    position_result: dict[str, Any],
    risk_score: float,
    risk_features: dict[str, Any] | None,
) -> dict[str, Any]:
    """基于轨迹风险分值动态选择滑块重合率门槛。

    决策树：
    - risk_score >= 0.7：高危机器轨迹，即使命中缺口也拒绝。
    - risk_score <= 0.3：优质人类轨迹，重合率 >= 0.70 即放行。
    - 其余模糊轨迹：使用标准重合率 >= 0.85。
    """

    overlap_ratio = float(position_result.get("overlap_ratio", 0.0))
    position_features = position_result.get("features")

    if risk_score >= HIGH_RISK_SCORE_THRESHOLD:
        return {
            "ok": False,
            "reason": "high_risk_slider_trajectory",
            "features": _merge_features(
                risk_features,
                position_features,
                {
                    "risk_score": round(risk_score, 6),
                    "risk_threshold": HIGH_RISK_SCORE_THRESHOLD,
                    "dynamic_decision": "reject_high_risk",
                },
            ),
        }

    required_overlap = (
        HUMAN_FRIENDLY_OVERLAP_RATIO
        if risk_score <= LOW_RISK_SCORE_THRESHOLD
        else STANDARD_OVERLAP_RATIO
    )
    if overlap_ratio < required_overlap:
        return {
            "ok": False,
            "reason": "slider_overlap_ratio_too_low",
            "features": _merge_features(
                risk_features,
                position_features,
                {
                    "risk_score": round(risk_score, 6),
                    "required_overlap": required_overlap,
                    "dynamic_decision": (
                        "low_risk_relaxed_reject"
                        if risk_score <= LOW_RISK_SCORE_THRESHOLD
                        else "standard_overlap_reject"
                    ),
                },
            ),
        }

    return {
        "ok": True,
        "reason": "passed",
        "features": _merge_features(
            risk_features,
            position_features,
            {
                "risk_score": round(risk_score, 6),
                "required_overlap": required_overlap,
                "dynamic_decision": (
                    "low_risk_relaxed_pass"
                    if risk_score <= LOW_RISK_SCORE_THRESHOLD
                    else "standard_overlap_pass"
                ),
            },
        ),
    }


def _parse_payload_captcha_type(plaintext: dict[str, Any]) -> dict[str, Any]:
    raw_type = plaintext.get("captcha_type")
    try:
        return {"ok": True, "captcha_type": CaptchaType(str(raw_type))}
    except ValueError:
        return {"ok": False, "reason": "unsupported_captcha_type"}


def _evaluate_tracks_or_fail(
    plaintext: dict[str, Any],
    *,
    bot_score_threshold: float = 0.65,
) -> dict[str, Any]:
    tracks = plaintext.get("tracks")
    fingerprint = plaintext.get("fingerprint")
    if not isinstance(tracks, list):
        return {"ok": False, "reason": "malformed_tracks"}
    if not isinstance(fingerprint, dict):
        return {"ok": False, "reason": "malformed_fingerprint"}

    risk_result = extract_trajectory_features(tracks, fingerprint)
    risk_score = float(risk_result["score"])
    if risk_result["is_bot"] and risk_score >= bot_score_threshold:
        return {
            "ok": False,
            "reason": risk_result["reason"],
            "risk_score": risk_score,
            "features": risk_result.get("features"),
        }

    return {
        "ok": True,
        "risk_score": risk_score,
        "features": risk_result.get("features"),
    }


def _issue_verify_signature(*, captcha_token: str, risk_score: float) -> str:
    verify_signature = f"vsig_{secrets.token_urlsafe(32)}"
    session_store.put_verify_signature(
        verify_signature=verify_signature,
        captcha_token=captcha_token,
        risk_score=risk_score,
        ttl_seconds=settings.verify_signature_ttl_seconds,
    )
    return verify_signature


def _verify_success_response(
    *,
    verify_signature: str,
    risk_score: float,
    features: dict[str, Any] | None,
    captcha_type: CaptchaType | str | None,
    plaintext: dict[str, Any] | None,
    overlap_ratio: float | None = None,
) -> CaptchaVerifyResponse:
    _log_verify_event(
        captcha_type=captcha_type,
        plaintext=plaintext,
        risk_score=risk_score,
        is_passed=True,
        reason="passed",
        overlap_ratio=overlap_ratio,
    )
    return CaptchaVerifyResponse(
        code=200,
        msg="success",
        data=CaptchaVerifyData(
            verify_signature=verify_signature,
            expires_in=settings.verify_signature_ttl_seconds,
            risk_score=risk_score,
            reason="passed",
            features=features,
        ),
    )


def _verify_failed_with_log(
    reason: str,
    *,
    captcha_type: CaptchaType | str | None,
    plaintext: dict[str, Any] | None,
    risk_score: float | None = None,
    features: dict[str, Any] | None = None,
    overlap_ratio: float | None = None,
) -> CaptchaVerifyResponse:
    _log_verify_event(
        captcha_type=captcha_type,
        plaintext=plaintext,
        risk_score=risk_score,
        is_passed=False,
        reason=reason,
        overlap_ratio=overlap_ratio,
    )
    return _verify_failed(reason, risk_score=risk_score, features=features)


def _log_verify_event(
    *,
    captcha_type: CaptchaType | str | None,
    plaintext: dict[str, Any] | None,
    risk_score: float | None,
    is_passed: bool,
    reason: str,
    overlap_ratio: float | None = None,
) -> None:
    log_trajectory_event_async(
        captcha_type=str(captcha_type) if captcha_type is not None else None,
        fingerprint=plaintext.get("fingerprint") if isinstance(plaintext, dict) else None,
        tracks=plaintext.get("tracks") if isinstance(plaintext, dict) else None,
        risk_score=risk_score,
        is_passed=is_passed,
        reason=reason,
        overlap_ratio=round(overlap_ratio, 6) if isinstance(overlap_ratio, float) else None,
        slider_x=_extract_slider_x(plaintext),
    )


def _merge_features(*parts: dict[str, Any] | None) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for part in parts:
        if isinstance(part, dict):
            merged.update(part)
    return merged


def _get_client_ip(request: Request) -> str:
    # 生产环境如果由 Nginx / Cloudflare 代理，应确保只信任可信代理写入的 X-Forwarded-For。
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def _allow_verify_request(client_ip: str) -> bool:
    now = time.monotonic()
    bucket = _verify_rate_buckets[client_ip]
    while bucket and now - bucket[0] >= VERIFY_RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= VERIFY_RATE_LIMIT:
        return False
    bucket.append(now)
    return True


def _extract_slider_x(plaintext: dict[str, Any] | None) -> float | None:
    if not isinstance(plaintext, dict) or "slider_x" not in plaintext:
        return None
    try:
        return float(plaintext["slider_x"])
    except (TypeError, ValueError):
        return None


def _precheck_failed(reason: str) -> CaptchaPrecheckResponse:
    return CaptchaPrecheckResponse(
        code=403,
        msg="failed",
        data=CaptchaPrecheckData(
            action="challenge",
            captcha_type=CaptchaType.SLIDER,
            verify_signature=None,
            expires_in=None,
            risk_score=1.0,
            reason=reason,
            challenge=None,
            features=None,
        ),
    )


def _verify_failed(
    reason: str,
    *,
    risk_score: float | None = None,
    features: dict[str, Any] | None = None,
) -> CaptchaVerifyResponse:
    return CaptchaVerifyResponse(
        code=403,
        msg="failed",
        data=CaptchaVerifyData(
            verify_signature=None,
            expires_in=None,
            risk_score=risk_score,
            reason=reason,
            features=features,
        ),
    )
