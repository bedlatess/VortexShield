from __future__ import annotations

import argparse
import json
import math
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.data_logger import is_valid_training_sample

DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "trajectory_data.jsonl"
PIECE_WIDTH = 53.0
BOOTSTRAP_SOURCE = "bootstrap_synthetic_human"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Append human-like slider samples to VortexShield trajectory logs.",
    )
    parser.add_argument("--passed", type=int, default=50, help="Number of human-correct samples to append.")
    parser.add_argument("--failed", type=int, default=30, help="Number of human-miss samples to append.")
    parser.add_argument("--seed", type=int, default=2026, help="Random seed for reproducible bootstrap data.")
    parser.add_argument(
        "--log-path",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help=f"Target JSONL log path. Default: {DEFAULT_LOG_PATH}",
    )
    parser.add_argument("--dry-run", action="store_true", help="Generate and print summary without writing JSONL.")
    args = parser.parse_args(argv)

    if args.passed < 0 or args.failed < 0:
        parser.error("--passed and --failed must be non-negative")

    records = build_bootstrap_records(passed=args.passed, failed=args.failed, seed=args.seed)
    summary = summarize_records(records)

    print("\n" + "=" * 72)
    print("VortexShield Training Log Bootstrap")
    print("=" * 72)
    print(f"human-correct samples : {summary['passed']}")
    print(f"human-miss samples    : {summary['failed']}")
    print(f"target log path       : {args.log_path}")
    print(f"dry run               : {args.dry_run}")

    if args.dry_run:
        print("[*] Dry run only. No log file was changed.")
        return 0

    append_records(args.log_path, records)
    print(f"[+] Appended {len(records)} bootstrap samples.")
    print("=" * 72 + "\n")
    return 0


def build_bootstrap_records(*, passed: int, failed: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    records: list[dict[str, Any]] = []

    for _ in range(passed):
        records.append(_make_record(rng, is_passed=True))

    for _ in range(failed):
        records.append(_make_record(rng, is_passed=False))

    rng.shuffle(records)
    return records


def append_records(log_path: Path, records: list[dict[str, Any]]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def summarize_records(records: list[dict[str, Any]]) -> dict[str, int]:
    passed = sum(1 for record in records if record.get("is_passed") is True)
    failed = sum(1 for record in records if record.get("is_passed") is False)
    return {"passed": passed, "failed": failed}


def _make_record(rng: random.Random, *, is_passed: bool) -> dict[str, Any]:
    for _attempt in range(50):
        target_x = rng.uniform(112.0, 246.0)
        if is_passed:
            offset = rng.uniform(-6.5, 6.5)
            reason = "bootstrap_human_passed"
            risk_score = round(rng.uniform(0.08, 0.22), 6)
        else:
            offset = rng.choice([-1.0, 1.0]) * rng.uniform(19.0, 34.0)
            reason = "bootstrap_human_slider_miss"
            risk_score = round(rng.uniform(0.10, 0.28), 6)

        slider_x = _clamp(target_x + offset, 0.0, 300.0)
        overlap_ratio = _calculate_overlap_ratio(slider_x=slider_x, target_x=target_x)
        tracks = generate_human_like_tracks(rng, slider_x=slider_x)

        # 这里复用线上 data_logger 的防投毒过滤器，确保引导样本不会绕开生产质量门槛。
        if is_valid_training_sample(tracks, slider_x):
            return {
                "event_time": datetime.now(timezone.utc).isoformat(),
                "captcha_type": "SLIDER",
                "fingerprint": _make_clean_fingerprint(rng),
                "tracks": tracks,
                "risk_score": risk_score,
                "overlap_ratio": round(overlap_ratio, 6),
                "slider_x": round(slider_x, 3),
                "is_passed": is_passed,
                "reason": reason,
                "sample_source": BOOTSTRAP_SOURCE,
            }

    raise RuntimeError("failed to generate a valid human-like training sample")


def generate_human_like_tracks(rng: random.Random, *, slider_x: float) -> list[list[float | int]]:
    """生成带非匀速、停顿、轻微回拉和 Y 轴微颤的真人拖拽轨迹。

    event_type 约定沿用 SDK：1=mousedown，0=mousemove，2=mouseup。
    这些样本用于补齐早期训练集，不代表真实用户；通过 sample_source 字段可在后续分析中筛出。
    """

    points: list[list[float | int]] = []
    x = rng.uniform(0.0, 4.0)
    y = rng.uniform(16.0, 31.0)
    timestamp = rng.uniform(0.0, 20.0)
    steps = rng.randint(22, 46)
    ease_power = rng.uniform(1.65, 2.85)

    points.append([round(x, 3), round(y, 3), round(timestamp, 3), 1])

    for index in range(1, steps + 1):
        progress = index / steps
        eased = 1.0 - (1.0 - progress) ** ease_power
        expected_x = slider_x * eased

        local_noise = rng.uniform(-2.8, 2.8)
        if index > steps * 0.72 and rng.random() < 0.20:
            local_noise -= rng.uniform(0.6, 2.4)
        if index > steps * 0.88 and rng.random() < 0.28:
            local_noise += rng.uniform(-1.4, 1.4)

        x = _clamp(expected_x + local_noise, 0.0, 300.0)
        y = _clamp(y + rng.uniform(-1.25, 1.25), 4.0, 48.0)

        # 鼠标采样间隔故意加入波动，防止形成完美匀速或固定帧率的脚本特征。
        timestamp += rng.uniform(14.0, 83.0)
        points.append([round(x, 3), round(y, 3), round(timestamp, 3), 0])

    timestamp += rng.uniform(45.0, 180.0)
    y = _clamp(y + rng.uniform(-0.8, 0.8), 4.0, 48.0)
    points.append([round(slider_x, 3), round(y, 3), round(timestamp, 3), 2])
    return points


def _make_clean_fingerprint(rng: random.Random) -> dict[str, Any]:
    profile = rng.choice(
        [
            ("chrome", "Win32", "zh-CN", "Asia/Shanghai", "1920x1080x24", 1),
            ("edge", "Win32", "zh-CN", "Asia/Shanghai", "2560x1440x24", 1),
            ("chrome", "MacIntel", "zh-CN", "Asia/Shanghai", "1440x900x24", 2),
            ("safari", "MacIntel", "en-US", "Asia/Shanghai", "1728x1117x24", 2),
        ]
    )
    ua_family, platform, language, timezone_name, screen, device_pixel_ratio = profile

    return {
        "ua_family": ua_family,
        "ua_length": rng.randint(92, 132),
        "language": language,
        "platform": platform,
        "timezone": timezone_name,
        "screen": screen,
        "device_pixel_ratio": device_pixel_ratio,
        "webdriver": False,
        "webdriver_descriptor_tampered": False,
        "machine_flag": False,
        "automation_globals_count": 0,
        "probe_notes_count": 0,
        "canvas_id_hash": f"{rng.getrandbits(32):08x}",
        "webgl_vendor_hash": f"{rng.getrandbits(32):08x}",
        "webgl_renderer_hash": f"{rng.getrandbits(32):08x}",
    }


def _calculate_overlap_ratio(*, slider_x: float, target_x: float) -> float:
    if not all(math.isfinite(value) for value in (slider_x, target_x)):
        return 0.0
    return max(0.0, 1.0 - abs(slider_x - target_x) / PIECE_WIDTH)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


if __name__ == "__main__":
    raise SystemExit(main())
