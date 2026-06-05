import json

from app.services import data_logger


def _valid_tracks() -> list[list[int]]:
    return [
        [0, 136, 0, 1],
        [22, 137, 120, 0],
        [58, 136, 260, 0],
        [94, 135, 430, 0],
        [132, 136, 620, 2],
    ]


def test_training_sample_filter_accepts_human_like_drag() -> None:
    assert data_logger.is_valid_training_sample(_valid_tracks(), slider_x=132)


def test_training_sample_filter_rejects_absolute_garbage() -> None:
    assert not data_logger.is_valid_training_sample(_valid_tracks()[:4], slider_x=132)

    too_fast = [[0, 136, 0, 1], [10, 136, 20, 0], [20, 136, 40, 0], [30, 136, 60, 0], [40, 136, 80, 2]]
    assert not data_logger.is_valid_training_sample(too_fast, slider_x=40)

    too_slow = [[0, 136, 0, 1], [10, 136, 4000, 0], [20, 136, 8000, 0], [30, 136, 12000, 0], [40, 136, 16001, 2]]
    assert not data_logger.is_valid_training_sample(too_slow, slider_x=40)

    assert not data_logger.is_valid_training_sample(_valid_tracks(), slider_x=-1)
    assert not data_logger.is_valid_training_sample(_valid_tracks(), slider_x=301)

    no_x_displacement = [[10, 136, 0, 1], [10, 137, 130, 0], [10, 136, 260, 0], [10, 137, 420, 0], [10, 136, 620, 2]]
    assert not data_logger.is_valid_training_sample(no_x_displacement, slider_x=10)

    wild_y = [[0, 80, 0, 1], [20, 136, 130, 0], [40, 150, 260, 0], [60, 170, 420, 0], [80, 136, 620, 2]]
    assert not data_logger.is_valid_training_sample(wild_y, slider_x=80)


def test_log_writer_drops_invalid_sample(tmp_path, monkeypatch) -> None:
    log_path = tmp_path / "trajectory_data.jsonl"
    monkeypatch.setattr(data_logger, "LOG_PATH", log_path)

    data_logger.log_trajectory_event_async(
        captcha_type="SLIDER",
        fingerprint={},
        tracks=_valid_tracks()[:2],
        risk_score=1.0,
        overlap_ratio=0.0,
        slider_x=999,
        is_passed=False,
        reason="garbage",
    )

    assert not log_path.exists()


def test_log_writer_persists_valid_sample(tmp_path, monkeypatch) -> None:
    log_path = tmp_path / "trajectory_data.jsonl"
    monkeypatch.setattr(data_logger, "LOG_PATH", log_path)

    data_logger.log_trajectory_event_async(
        captcha_type="SLIDER",
        fingerprint={"ua": "Mozilla/5.0"},
        tracks=_valid_tracks(),
        risk_score=0.12,
        overlap_ratio=0.91,
        slider_x=132,
        is_passed=True,
        reason="passed",
    )

    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert record["captcha_type"] == "SLIDER"
    assert record["slider_x"] == 132
    assert record["overlap_ratio"] == 0.91
    assert record["is_passed"] is True


def test_log_rotation_keeps_bounded_backups(tmp_path, monkeypatch) -> None:
    log_path = tmp_path / "trajectory_data.jsonl"
    monkeypatch.setattr(data_logger, "LOG_PATH", log_path)
    monkeypatch.setattr(data_logger, "MAX_LOG_SIZE", 20)
    monkeypatch.setattr(data_logger, "BACKUP_COUNT", 2)

    log_path.write_text("current-file-that-is-long-enough", encoding="utf-8")
    log_path.with_name("trajectory_data.jsonl.1").write_text("backup-one", encoding="utf-8")
    log_path.with_name("trajectory_data.jsonl.2").write_text("backup-two", encoding="utf-8")

    data_logger.log_trajectory_event_async(
        captcha_type="SLIDER",
        fingerprint={},
        tracks=_valid_tracks(),
        risk_score=0.12,
        overlap_ratio=0.88,
        slider_x=132,
        is_passed=True,
        reason="passed",
    )

    assert log_path.exists()
    assert log_path.with_name("trajectory_data.jsonl.1").read_text(encoding="utf-8") == "current-file-that-is-long-enough"
    assert log_path.with_name("trajectory_data.jsonl.2").read_text(encoding="utf-8") == "backup-one"
    assert json.loads(log_path.read_text(encoding="utf-8").strip())["reason"] == "passed"
