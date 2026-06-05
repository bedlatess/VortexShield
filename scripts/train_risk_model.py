from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "trajectory_data.jsonl"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "vsec_rf_model.pkl"

FEATURE_COLUMNS = [
    "track_count",
    "total_duration",
    "x_displacement",
    "y_displacement",
    "path_length",
    "straightness",
    "mean_velocity",
    "max_velocity",
    "velocity_std",
    "acceleration_variance",
    "dt_mean",
    "dt_std",
    "down_count",
    "move_count",
    "up_count",
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VortexShield 轨迹风控随机森林训练脚本",
    )
    parser.add_argument(
        "--log-path",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help=f"轨迹 JSONL 日志路径，默认 {DEFAULT_LOG_PATH}",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help=f"模型输出路径，默认 {DEFAULT_MODEL_PATH}",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=80,
        help="样本少于该数量时自动补充合成样本，保证训练链路始终可跑通。",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=2026,
        help="随机种子，便于重复训练和复现实验结果。",
    )
    args = parser.parse_args()

    random.seed(args.random_state)

    print_banner("VortexShield Risk Model Training")
    records = load_jsonl_records(args.log_path)
    print(f"[*] 读取日志样本: {len(records)} 条")

    dataset = build_dataset(records)
    dataset = ensure_training_volume(
        dataset,
        min_samples=args.min_samples,
        random_state=args.random_state,
    )

    if dataset["label"].nunique() < 2:
        # 极端情况下日志全是同一类，随机森林无法学习二分类边界。这里补一组对立样本兜底。
        missing_label = 1 if int(dataset["label"].iloc[0]) == 0 else 0
        dataset = pd.concat(
            [dataset, synthetic_dataset(20, label=missing_label, random_state=args.random_state + 7)],
            ignore_index=True,
        )

    train_and_save_model(dataset, args.model_path, random_state=args.random_state)
    return 0


def load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    """读取 JSON Lines 轨迹日志。

    data_logger.py 每行写入一条 verify 事件。线上如果日志中混入半行或损坏 JSON，
    训练脚本会跳过坏行，避免一次异常写入影响整批训练。
    """

    if not path.exists():
        print(f"[!] 未找到日志文件: {path}")
        return []

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line_no, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(f"[!] 跳过损坏日志行: line={line_no}")
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def build_dataset(records: list[dict[str, Any]]) -> pd.DataFrame:
    """把原始日志转换成模型可训练的表格数据。

    标签约定：
    - is_passed=True  -> label=0，代表正常真人/可信行为。
    - is_passed=False -> label=1，代表异常、机器行为或验证失败样本。
    - 如果没有 is_passed，则使用 risk_score 兜底，risk_score >= 0.65 视为异常。
    """

    rows: list[dict[str, float | int | str]] = []
    for record in records:
        tracks = record.get("tracks")
        if not isinstance(tracks, list):
            tracks = []

        features = extract_track_features(tracks)
        label = infer_label(record)
        row: dict[str, float | int | str] = {
            **features,
            "label": label,
            "captcha_type": str(record.get("captcha_type") or "UNKNOWN"),
            "reason": str(record.get("reason") or ""),
        }
        rows.append(row)

    if not rows:
        return pd.DataFrame(columns=[*FEATURE_COLUMNS, "label", "captcha_type", "reason"])
    return pd.DataFrame(rows)


def extract_track_features(tracks: list[Any]) -> dict[str, float]:
    """从轨迹数组提取机器学习特征。

    tracks 点格式为 [x, y, timestamp, event_type]。

    与 risk_engine.py 的关系：
    - 当前 risk_engine.py 手写判断 velocity_std 和 max_velocity。
    - 未来接入 AI 模型时，可以在 risk_engine.py 中复用本函数或提取为公共模块，
      对前端提交的 tracks 做同样的特征转换，再加载 models/vsec_rf_model.pkl 输出 Bot 概率。
    - 模型输出可以作为硬规则之后的第二层判定，例如 predict_proba(...)[1] > 0.72 即拦截。
    """

    clean_points = normalize_track_points(tracks)
    if not clean_points:
        return zero_features()

    x_values = [point[0] for point in clean_points]
    y_values = [point[1] for point in clean_points]
    t_values = [point[2] for point in clean_points]
    event_values = [point[3] for point in clean_points]

    velocities: list[float] = []
    accelerations: list[float] = []
    dt_values: list[float] = []
    distances: list[float] = []

    for index in range(1, len(clean_points)):
        prev = clean_points[index - 1]
        curr = clean_points[index]
        dx = curr[0] - prev[0]
        dy = curr[1] - prev[1]
        dt = curr[2] - prev[2]

        # 浏览器上报时间戳偶尔可能出现重复或异常，这里跳过非正 dt，
        # 防止速度分母为 0，把正常样本污染成无限大速度。
        if dt <= 0:
            continue

        distance = math.hypot(dx, dy)
        velocity = distance / dt
        dt_values.append(dt)
        distances.append(distance)
        velocities.append(velocity)

        if len(velocities) >= 2:
            accelerations.append((velocities[-1] - velocities[-2]) / dt)

    direct_distance = math.hypot(
        x_values[-1] - x_values[0],
        y_values[-1] - y_values[0],
    )
    path_length = sum(distances)

    # straightness 越接近 1，越像机械直线；真人轨迹通常因为停顿、微颤、回拉而低一些。
    straightness = direct_distance / path_length if path_length > 0 else 0.0

    return {
        "track_count": float(len(clean_points)),
        "total_duration": float(max(t_values) - min(t_values)) if len(t_values) >= 2 else 0.0,
        "x_displacement": float(x_values[-1] - x_values[0]),
        "y_displacement": float(y_values[-1] - y_values[0]),
        "path_length": float(path_length),
        "straightness": float(straightness),
        "mean_velocity": float(mean(velocities)) if velocities else 0.0,
        "max_velocity": float(max(velocities)) if velocities else 0.0,
        "velocity_std": float(pstdev(velocities)) if len(velocities) > 1 else 0.0,
        "acceleration_variance": float(pvariance(accelerations)) if len(accelerations) > 1 else 0.0,
        "dt_mean": float(mean(dt_values)) if dt_values else 0.0,
        "dt_std": float(pstdev(dt_values)) if len(dt_values) > 1 else 0.0,
        "down_count": float(event_values.count(1)),
        "move_count": float(event_values.count(0)),
        "up_count": float(event_values.count(2)),
    }


def normalize_track_points(tracks: list[Any]) -> list[tuple[float, float, float, int]]:
    clean_points: list[tuple[float, float, float, int]] = []
    for point in tracks:
        if not isinstance(point, (list, tuple)) or len(point) < 4:
            continue
        try:
            x = float(point[0])
            y = float(point[1])
            timestamp = float(point[2])
            event_type = int(point[3])
        except (TypeError, ValueError):
            continue
        if all(math.isfinite(value) for value in (x, y, timestamp)):
            clean_points.append((x, y, timestamp, event_type))
    return clean_points


def zero_features() -> dict[str, float]:
    return {name: 0.0 for name in FEATURE_COLUMNS}


def infer_label(record: dict[str, Any]) -> int:
    is_passed = record.get("is_passed")
    if is_passed is True:
        return 0
    if is_passed is False:
        return 1

    risk_score = record.get("risk_score")
    try:
        return 1 if float(risk_score) >= 0.65 else 0
    except (TypeError, ValueError):
        return 1


def ensure_training_volume(
    dataset: pd.DataFrame,
    *,
    min_samples: int,
    random_state: int,
) -> pd.DataFrame:
    """样本不足时补充合成数据。

    早期项目通常只有几十条联调样本，直接训练会不稳定，甚至因为类别缺失而失败。
    这里生成两类 Synthetic Data：
    - 正样本：模拟真人拖动，dt 和 dx 有自然波动，Y 轴有微小抖动。
    - 负样本：模拟匀速直线、瞬移、空轨迹等攻击/异常样本。
    这些样本只用于打通训练链路；真实生产模型应逐步提高真实日志占比。
    """

    current = len(dataset)
    if current >= min_samples and dataset["label"].nunique() >= 2:
        return dataset

    needed = max(min_samples - current, 20)
    normal_count = needed // 2
    bot_count = needed - normal_count
    print(f"[*] 样本不足或类别不均衡，自动补充合成样本: normal={normal_count}, bot={bot_count}")

    synthetic = pd.concat(
        [
            synthetic_dataset(normal_count, label=0, random_state=random_state),
            synthetic_dataset(bot_count, label=1, random_state=random_state + 1),
        ],
        ignore_index=True,
    )
    return pd.concat([dataset, synthetic], ignore_index=True)


def synthetic_dataset(count: int, *, label: int, random_state: int) -> pd.DataFrame:
    rng = random.Random(random_state)
    rows: list[dict[str, float | int | str]] = []
    for _ in range(count):
        if label == 0:
            tracks = generate_human_like_tracks(rng)
            reason = "synthetic_human"
        else:
            tracks = generate_bot_like_tracks(rng)
            reason = "synthetic_bot"

        rows.append(
            {
                **extract_track_features(tracks),
                "label": label,
                "captcha_type": "SYNTHETIC",
                "reason": reason,
            }
        )
    return pd.DataFrame(rows)


def generate_human_like_tracks(rng: random.Random) -> list[list[float | int]]:
    """生成带微颤、非匀速和轻微回拉的人类拖动轨迹。"""

    points: list[list[float | int]] = []
    x = 0.0
    y = rng.uniform(126, 142)
    timestamp = 0.0
    target = rng.uniform(115, 230)
    steps = rng.randint(12, 28)

    points.append([round(x, 3), round(y, 3), round(timestamp, 3), 1])
    for index in range(1, steps + 1):
        progress = index / steps
        # ease-out 让前段快、后段慢，叠加随机噪声，更接近真实拖拽。
        expected_x = target * (1 - (1 - progress) ** 2)
        x = max(0.0, expected_x + rng.uniform(-2.8, 2.8))
        if index in {steps - 2, steps - 1} and rng.random() < 0.45:
            x -= rng.uniform(0.5, 2.2)
        y += rng.uniform(-1.15, 1.15)
        timestamp += rng.uniform(18, 82)
        points.append([round(x, 3), round(y, 3), round(timestamp, 3), 0])

    timestamp += rng.uniform(40, 160)
    points.append([round(target + rng.uniform(-3, 3), 3), round(y, 3), round(timestamp, 3), 2])
    return points


def generate_bot_like_tracks(rng: random.Random) -> list[list[float | int]]:
    """生成典型机器轨迹：匀速直线、瞬移或极短轨迹。"""

    attack_type = rng.choice(["uniform", "teleport", "short"])
    if attack_type == "short":
        return [[0, 136, 0, 1], [rng.uniform(150, 230), 136, rng.uniform(1, 6), 2]]

    if attack_type == "teleport":
        distance = rng.uniform(140, 240)
        return [
            [0, 136, 0, 1],
            [distance, 136, rng.uniform(2, 5), 0],
            [distance, 136, rng.uniform(7, 15), 2],
        ]

    distance = rng.uniform(120, 230)
    steps = rng.randint(8, 22)
    fixed_dt = rng.uniform(8, 18)
    fixed_dx = distance / steps
    points: list[list[float | int]] = [[0, 136, 0, 1]]
    for index in range(1, steps + 1):
        points.append([round(fixed_dx * index, 3), 136, round(fixed_dt * index, 3), 0])
    points.append([round(distance, 3), 136, round(fixed_dt * (steps + 1), 3), 2])
    return points


def train_and_save_model(dataset: pd.DataFrame, model_path: Path, *, random_state: int) -> None:
    x = dataset[FEATURE_COLUMNS].fillna(0.0)
    y = dataset["label"].astype(int)

    stratify = y if y.nunique() >= 2 and y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        random_state=random_state,
        stratify=stratify,
    )

    # RandomForest 本身不依赖标准化；这里仍用 Pipeline 封装，方便未来替换为
    # LogisticRegression、SVM、XGBoost 等需要预处理的模型时保持同一序列化接口。
    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=180,
                    max_depth=8,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    random_state=random_state,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 78)
    print(f"[+] 模型训练完成，Accuracy: {accuracy:.4f}")
    print("-" * 78)
    print(classification_report(y_test, y_pred, target_names=["human", "bot"], zero_division=0))

    classifier: RandomForestClassifier = model.named_steps["classifier"]
    importances = sorted(
        zip(FEATURE_COLUMNS, classifier.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )
    print("特征重要性排名:")
    for rank, (name, importance) in enumerate(importances, start=1):
        print(f"{rank:02d}. {name:<24} {importance:.6f}")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "label_mapping": {"human": 0, "bot": 1},
            "notes": (
                "risk_engine.py 在线接入时，应先调用同等特征提取逻辑生成 DataFrame，"
                "再使用 payload['model'].predict_proba(features)[0][1] 获取 Bot 概率。"
            ),
        },
        model_path,
    )
    print("-" * 78)
    print(f"[+] 模型已保存: {model_path}")
    print("=" * 78 + "\n")


def print_banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


if __name__ == "__main__":
    raise SystemExit(main())
