import json

from app.services.data_logger import is_valid_training_sample
from scripts import seed_training_logs
from scripts.train_risk_model import infer_label


def test_seed_training_logs_builds_human_pass_and_miss_samples() -> None:
    records = seed_training_logs.build_bootstrap_records(passed=6, failed=4, seed=2026)

    assert len(records) == 10
    assert sum(1 for record in records if record["is_passed"] is True) == 6
    assert sum(1 for record in records if record["is_passed"] is False) == 4

    for record in records:
        assert record["captcha_type"] == "SLIDER"
        assert record["sample_source"] == seed_training_logs.BOOTSTRAP_SOURCE
        assert record["fingerprint"]["webdriver"] is False
        assert record["fingerprint"]["automation_globals_count"] == 0
        assert is_valid_training_sample(record["tracks"], record["slider_x"])

        if record["is_passed"]:
            assert record["reason"] == "bootstrap_human_passed"
            assert record["overlap_ratio"] >= 0.85
            assert record["risk_score"] <= 0.3
        else:
            assert record["reason"] == "bootstrap_human_slider_miss"
            assert record["overlap_ratio"] < 0.70
            assert record["risk_score"] <= 0.3


def test_seed_training_logs_appends_jsonl(tmp_path) -> None:
    log_path = tmp_path / "trajectory_data.jsonl"
    records = seed_training_logs.build_bootstrap_records(passed=2, failed=1, seed=7)

    seed_training_logs.append_records(log_path, records)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    loaded = [json.loads(line) for line in lines]
    assert {record["reason"] for record in loaded} == {
        "bootstrap_human_passed",
        "bootstrap_human_slider_miss",
    }


def test_training_label_treats_low_risk_human_miss_as_human_behavior() -> None:
    assert infer_label({"is_passed": False, "risk_score": 0.16, "reason": "bootstrap_human_slider_miss"}) == 0
    assert infer_label({"is_passed": False, "risk_score": 0.18, "reason": "slider_overlap_ratio_too_low"}) == 0
    assert infer_label({"is_passed": False, "risk_score": 1.0, "reason": "automation_probe_detected"}) == 1
