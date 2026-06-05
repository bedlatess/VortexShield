from __future__ import annotations

import asyncio
import json
import math
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOG_PATH = Path("logs") / "trajectory_data.jsonl"
MAX_TRACK_POINTS = 800
MAX_LOG_SIZE = 10 * 1024 * 1024
BACKUP_COUNT = 5
MIN_TRACK_POINTS = 5
MIN_DURATION_MS = 100
MAX_DURATION_MS = 15_000
MAX_SLIDER_X = 300.0
MAX_Y_SWING = 53.0
_write_lock = threading.Lock()


def log_trajectory_event_async(
    *,
    captcha_type: str | None,
    fingerprint: dict[str, Any] | None,
    tracks: list[Any] | None,
    risk_score: float | None,
    is_passed: bool,
    reason: str,
    overlap_ratio: float | None = None,
    slider_x: float | None = None,
) -> None:
    """异步追加轨迹样本日志。

    API 层只负责调度，不等待文件 IO 完成。即使日志写入失败，也不能影响验证码响应。
    生产环境可将这里替换为 Kafka、Redis Stream 或对象存储批量写入。
    """

    sanitized_tracks = _sanitize_tracks(tracks)
    if not is_valid_training_sample(sanitized_tracks, slider_x):
        return

    record = {
        "event_time": datetime.now(timezone.utc).isoformat(),
        "captcha_type": captcha_type,
        "fingerprint": _sanitize_fingerprint(fingerprint),
        "tracks": sanitized_tracks,
        "risk_score": risk_score,
        "overlap_ratio": overlap_ratio,
        "slider_x": slider_x,
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
        with _write_lock:
            _rotate_logs_if_needed()
            with LOG_PATH.open("a", encoding="utf-8") as file:
                file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError:
        # 日志是数据飞轮的旁路资产，不能因为磁盘错误拖垮主验证链路。
        return


def is_valid_training_sample(tracks: list[Any] | None, slider_x: float | int | None) -> bool:
    """过滤明显不适合作为训练样本的脏数据。

    这个函数只拦截“绝对垃圾数据”：极短轨迹、异常耗时、明显越界和不可能的人类拖拽。
    目的不是替代风控判定，而是防止攻击者用批量脚本向 JSONL 数据飞轮灌入投毒样本。
    """

    if not isinstance(tracks, list) or len(tracks) < MIN_TRACK_POINTS:
        return False

    points = _normalize_track_points(tracks)
    if len(points) < MIN_TRACK_POINTS:
        return False

    duration = points[-1][2] - points[0][2]
    if duration < MIN_DURATION_MS or duration > MAX_DURATION_MS:
        return False

    try:
        slider_x_value = float(slider_x)
    except (TypeError, ValueError):
        return False
    if not math.isfinite(slider_x_value) or slider_x_value < 0 or slider_x_value > MAX_SLIDER_X:
        return False

    x_values = [point[0] for point in points]
    y_values = [point[1] for point in points]
    x_displacement = abs(x_values[-1] - x_values[0])
    y_swing = max(y_values) - min(y_values)

    if x_displacement <= 0:
        return False
    if y_swing > MAX_Y_SWING:
        return False

    return True


def _normalize_track_points(tracks: list[Any]) -> list[tuple[float, float, float, int]]:
    points: list[tuple[float, float, float, int]] = []
    for raw in tracks:
        if not isinstance(raw, (list, tuple)) or len(raw) < 4:
            continue
        try:
            x = float(raw[0])
            y = float(raw[1])
            timestamp = float(raw[2])
            event_type = int(raw[3])
        except (TypeError, ValueError):
            continue
        if all(math.isfinite(value) for value in (x, y, timestamp)):
            points.append((x, y, timestamp, event_type))
    return points


def _rotate_logs_if_needed() -> None:
    if not LOG_PATH.exists() or LOG_PATH.stat().st_size <= MAX_LOG_SIZE:
        return

    oldest_backup = LOG_PATH.with_name(f"{LOG_PATH.name}.{BACKUP_COUNT}")
    if oldest_backup.exists():
        oldest_backup.unlink()

    for index in range(BACKUP_COUNT - 1, 0, -1):
        source = LOG_PATH.with_name(f"{LOG_PATH.name}.{index}")
        target = LOG_PATH.with_name(f"{LOG_PATH.name}.{index + 1}")
        if source.exists():
            source.replace(target)

    LOG_PATH.replace(LOG_PATH.with_name(f"{LOG_PATH.name}.1"))


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
