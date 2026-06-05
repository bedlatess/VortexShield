from __future__ import annotations

import math
from statistics import mean, pstdev, pvariance
from typing import Any

from app.core.enums import RiskLevel


BOT_SCORE = 1.0
PASS_SCORE = 0.12


def evaluate_environment(fingerprint: dict[str, Any]) -> dict[str, Any]:
    """静默环境预检，输出 LOW/MEDIUM/HIGH 三档风险。

    分流策略：
    - LOW：基础浏览器字段完整，且没有 webdriver/自动化全局变量等探针命中。
    - MEDIUM：没有明确 Bot 证据，但 UA、语言、平台、Canvas/WebGL 等信号缺失或偏弱。
    - HIGH：出现 webdriver、fake_webdriver、machine_flag、automation globals 等明确自动化特征。
    """

    if not isinstance(fingerprint, dict):
        return {
            "risk_level": RiskLevel.HIGH,
            "score": 1.0,
            "reason": "malformed_fingerprint",
            "features": {},
        }

    probe_result = _detect_automation_probe(fingerprint)
    if probe_result:
        return {
            "risk_level": RiskLevel.HIGH,
            "score": 1.0,
            "reason": "automation_probe_detected",
            "features": probe_result,
        }

    ua = str(fingerprint.get("ua") or "").strip()
    language = str(fingerprint.get("language") or "").strip()
    platform = str(fingerprint.get("platform") or "").strip()
    if len(ua) < 12 or ua.lower() in {"unknown", "null", "undefined"}:
        return {
            "risk_level": RiskLevel.MEDIUM,
            "score": 0.58,
            "reason": "invalid_user_agent",
            "features": {"ua": ua},
        }
    if not language or not platform:
        return {
            "risk_level": RiskLevel.MEDIUM,
            "score": 0.52,
            "reason": "incomplete_browser_environment",
            "features": {"language": language, "platform": platform},
        }

    canvas_id = str(fingerprint.get("canvas_id") or "").strip()
    webgl_vendor = str(fingerprint.get("webgl_vendor") or "").strip()
    webgl_renderer = str(fingerprint.get("webgl_renderer") or "").strip()
    weak_signals: dict[str, Any] = {}
    if not canvas_id or canvas_id in {"canvas-unavailable", "unknown"}:
        weak_signals["canvas_id"] = canvas_id
    if not webgl_vendor or not webgl_renderer:
        weak_signals["webgl"] = {"vendor": webgl_vendor, "renderer": webgl_renderer}
    if weak_signals:
        return {
            "risk_level": RiskLevel.MEDIUM,
            "score": 0.46,
            "reason": "weak_browser_fingerprint",
            "features": weak_signals,
        }

    return {
        "risk_level": RiskLevel.LOW,
        "score": 0.08,
        "reason": "clean_environment",
        "features": {
            "ua_present": True,
            "language": language,
            "platform": platform,
            "webdriver": False,
        },
    }


def extract_trajectory_features(
    tracks: list[list[float | int]],
    fingerprint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """提取轨迹统计学特征并执行硬拦截。

    tracks 每个点格式为 [x, y, timestamp, event_type]。

    一阶速度：
        v_i = sqrt((x_i - x_{i-1})^2 + (y_i - y_{i-1})^2) / dt

    二阶加速度：
        a_i = (v_i - v_{i-1}) / dt

    这里继续保留 Phase 3 的风控能力，后续滑块拖动校验可以直接复用。
    """

    fingerprint = fingerprint or {}
    probe_result = _detect_automation_probe(fingerprint)
    if probe_result:
        return _blocked("automation_probe_detected", features=probe_result)

    if len(tracks) < 5:
        return _blocked(
            "insufficient_track_length",
            features={"track_count": len(tracks), "min_required": 5},
        )

    velocities: list[float] = []
    accelerations: list[float] = []
    deltas_t: list[float] = []
    distances: list[float] = []

    for index in range(1, len(tracks)):
        prev = tracks[index - 1]
        curr = tracks[index]
        try:
            dx = float(curr[0]) - float(prev[0])
            dy = float(curr[1]) - float(prev[1])
            dt = float(curr[2]) - float(prev[2])
        except (TypeError, ValueError, IndexError) as exc:
            return _blocked("malformed_track_point", features={"index": index, "error": str(exc)})

        if dt <= 0:
            return _blocked("non_monotonic_timestamp", features={"index": index, "dt": dt})

        distance = math.hypot(dx, dy)
        velocity = distance / dt
        deltas_t.append(dt)
        distances.append(distance)
        velocities.append(velocity)

        if len(velocities) >= 2:
            acceleration = (velocities[-1] - velocities[-2]) / dt
            accelerations.append(acceleration)

    moved = any(distance > 0 for distance in distances)
    v_mean = mean(velocities) if velocities else 0.0
    v_std = pstdev(velocities) if len(velocities) > 1 else 0.0
    v_max = max(velocities) if velocities else 0.0
    a_var = pvariance(accelerations) if len(accelerations) > 1 else 0.0
    dt_mean = mean(deltas_t) if deltas_t else 0.0
    dt_std = pstdev(deltas_t) if len(deltas_t) > 1 else 0.0

    features = {
        "track_count": len(tracks),
        "velocity_mean": round(v_mean, 6),
        "velocity_std": round(v_std, 6),
        "velocity_max": round(v_max, 6),
        "acceleration_variance": round(a_var, 6),
        "dt_mean": round(dt_mean, 6),
        "dt_std": round(dt_std, 6),
        "moved": moved,
    }

    if moved and v_std < 0.001:
        return _blocked("static_uniform_motion_detected", features=features)

    if v_max > 40.0:
        return _blocked("teleportation_detected", features=features)

    risk_score = _infer_lightweight_score(v_std=v_std, a_var=a_var, dt_std=dt_std)
    return {
        "is_bot": risk_score > 0.65,
        "score": risk_score,
        "reason": "risk_score_threshold" if risk_score > 0.65 else "passed",
        "features": features,
    }


def _detect_automation_probe(fingerprint: dict[str, Any]) -> dict[str, Any] | None:
    flagged_fields: dict[str, Any] = {}
    for key in ("webdriver", "webdriver_descriptor_tampered", "machine_flag", "fake_webdriver"):
        if fingerprint.get(key) is True:
            flagged_fields[key] = True

    automation_globals = fingerprint.get("automation_globals")
    if isinstance(automation_globals, list) and automation_globals:
        flagged_fields["automation_globals"] = automation_globals

    probe_notes = fingerprint.get("probe_notes")
    if isinstance(probe_notes, list) and probe_notes:
        suspicious_notes = [
            note
            for note in probe_notes
            if "webdriver" in str(note).lower() or "automation" in str(note).lower()
        ]
        if suspicious_notes:
            flagged_fields["probe_notes"] = suspicious_notes

    return flagged_fields or None


def _infer_lightweight_score(v_std: float, a_var: float, dt_std: float) -> float:
    if v_std < 0.02 and a_var < 0.0001 and dt_std < 0.5:
        return 0.82
    if v_std < 0.05 and a_var < 0.0005:
        return 0.58
    return PASS_SCORE


def _blocked(reason: str, features: dict[str, Any]) -> dict[str, Any]:
    return {
        "is_bot": True,
        "score": BOT_SCORE,
        "reason": reason,
        "features": features,
    }
