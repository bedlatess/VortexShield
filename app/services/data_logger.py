from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOG_PATH = Path("logs") / "trajectory_data.jsonl"
MAX_TRACK_POINTS = 800


def log_trajectory_event_async(
    *,
    captcha_type: str | None,
    fingerprint: dict[str, Any] | None,
    tracks: list[Any] | None,
    risk_score: float | None,
    is_passed: bool,
    reason: str,
) -> None:
    """异步追加轨迹样本日志。

    API 层只负责调度，不等待文件 IO 完成。即使日志写入失败，也不能影响验证码响应。
    生产环境可将这里替换为 Kafka、Redis Stream 或对象存储批量写入。
    """

    record = {
        "event_time": datetime.now(timezone.utc).isoformat(),
        "captcha_type": captcha_type,
        "fingerprint": _sanitize_fingerprint(fingerprint),
        "tracks": _sanitize_tracks(tracks),
        "risk_score": risk_score,
        "is_passed": is_passed,
        "reason": reason,
    }

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # TestClient/脚本环境可能没有正在运行的事件循环；这里仍然兜底同步写一次。
        _append_jsonl(record)
        return

    loop.run_in_executor(None, _append_jsonl, record)


def _append_jsonl(record: dict[str, Any]) -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError:
        # 日志是数据飞轮的旁路资产，不能因为磁盘错误拖垮主验证链路。
        return


def _sanitize_fingerprint(fingerprint: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(fingerprint, dict):
        return {}

    ua = str(fingerprint.get("ua") or "")
    sanitized = {
        "ua_family": _infer_ua_family(ua),
        "ua_length": len(ua),
        "language": _clip(fingerprint.get("language"), 24),
        "platform": _clip(fingerprint.get("platform"), 32),
        "timezone": _clip(fingerprint.get("timezone"), 48),
        "screen": _clip(fingerprint.get("screen"), 32),
        "device_pixel_ratio": fingerprint.get("device_pixel_ratio"),
        "webdriver": fingerprint.get("webdriver") is True,
        "webdriver_descriptor_tampered": fingerprint.get("webdriver_descriptor_tampered") is True,
        "machine_flag": fingerprint.get("machine_flag") is True,
        "automation_globals_count": _count_list(fingerprint.get("automation_globals")),
        "probe_notes_count": _count_list(fingerprint.get("probe_notes")),
        "canvas_id_hash": _stable_short_hash(fingerprint.get("canvas_id")),
        "webgl_vendor_hash": _stable_short_hash(fingerprint.get("webgl_vendor")),
        "webgl_renderer_hash": _stable_short_hash(fingerprint.get("webgl_renderer")),
    }
    return sanitized


def _sanitize_tracks(tracks: list[Any] | None) -> list[Any]:
    if not isinstance(tracks, list):
        return []
    return tracks[:MAX_TRACK_POINTS]


def _infer_ua_family(ua: str) -> str:
    lower = ua.lower()
    if "edg/" in lower:
        return "edge"
    if "chrome/" in lower:
        return "chrome"
    if "firefox/" in lower:
        return "firefox"
    if "safari/" in lower:
        return "safari"
    if not ua:
        return "missing"
    return "other"


def _clip(value: Any, max_length: int) -> str:
    text = str(value or "")
    return text[:max_length]


def _count_list(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _stable_short_hash(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    # 非密码学用途：只做脱敏聚合标识，避免直接落完整指纹。
    accumulator = 2166136261
    for char in text:
        accumulator ^= ord(char)
        accumulator = (accumulator * 16777619) & 0xFFFFFFFF
    return f"{accumulator:08x}"
