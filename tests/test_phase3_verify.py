import base64
import json
import secrets

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from app.core.enums import CaptchaType
from app.api.routes import captcha as captcha_routes
from app.main import app
from app.services.site_registry import DEFAULT_DEMO_SECRET
from app.services.session_store import session_store


DEMO_SITE_CONTEXT = {
    "site_key": "vsec_site_demo",
    "action": "login",
    "hostname": "localhost",
}


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets() -> None:
    captcha_routes._verify_rate_buckets.clear()


def _encrypt_payload(plaintext: dict, rsa_public_key_pem: str) -> dict:
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(iv, json.dumps(plaintext).encode("utf-8"), None)
    public_key = serialization.load_pem_public_key(rsa_public_key_pem.encode("ascii"))
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "version": "vsec-rsa-oaep-aes-gcm@phase5",
        "alg": "RSA-OAEP-2048-SHA256+A256GCM",
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "encrypted_payload": {
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
    }


def _make_challenge(client: TestClient) -> tuple[dict, object]:
    response = client.get(
        "/api/captcha/challenge",
        params=DEMO_SITE_CONTEXT,
    )
    assert response.status_code == 200
    data = response.json()["data"]
    session = session_store.get(data["captcha_token"])
    assert session is not None
    assert session.slider_answer is not None
    return data, session


def _make_precheck_key(client: TestClient) -> dict:
    response = client.get(
        "/api/captcha/precheck-key",
        params=DEMO_SITE_CONTEXT,
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["precheck_token"].startswith("pre_rsa_")
    assert "BEGIN PUBLIC KEY" in data["rsa_public_key"]
    return data


def _clean_fingerprint() -> dict:
    return {
        "ua": "Mozilla/5.0 Unit Test Browser",
        "language": "zh-CN",
        "platform": "Win32",
        "timezone": "Asia/Shanghai",
        "screen": "1920x1080x24",
        "device_pixel_ratio": 1,
        "webdriver": False,
        "webdriver_descriptor_tampered": False,
        "automation_globals": [],
        "canvas_id": "unit-test-canvas",
        "webgl_vendor": "test-vendor",
        "webgl_renderer": "test-renderer",
        "machine_flag": False,
        "probe_notes": [],
    }


def _human_like_tracks(target_x: int) -> list[list[int]]:
    return [
        [0, 136, 0, 1],
        [12, 136, 41, 0],
        [33, 137, 94, 0],
        [59, 136, 158, 0],
        [88, 135, 237, 0],
        [target_x - 20, 136, 329, 0],
        [target_x - 7, 136, 447, 0],
        [target_x, 136, 586, 2],
    ]


def _slider_plaintext(token: str, target_x: int, tracks: list[list[int]] | None = None) -> dict:
    return {
        "client_time": 1717834512000,
        **DEMO_SITE_CONTEXT,
        "captcha_token": token,
        "captcha_type": CaptchaType.SLIDER,
        "slider_x": target_x,
        "tracks": tracks or _human_like_tracks(target_x),
        "fingerprint": _clean_fingerprint(),
    }


def _checkbox_plaintext(token: str, tracks: list[list[int]] | None = None) -> dict:
    return {
        "client_time": 1717834512000,
        **DEMO_SITE_CONTEXT,
        "captcha_token": token,
        "captcha_type": CaptchaType.CLICK_CHECKBOX,
        "checkbox_checked": True,
        "tracks": tracks
        or [[4, 8, 1, 0], [18, 20, 37, 0], [31, 26, 91, 0], [42, 31, 156, 0], [48, 32, 244, 1], [48, 32, 315, 2]],
        "fingerprint": _clean_fingerprint(),
    }


def _verify(client: TestClient, token: str, rsa_public_key_pem: str, plaintext: dict):
    return client.post(
        "/api/captcha/verify",
        json={"captcha_token": token, "payload": _encrypt_payload(plaintext, rsa_public_key_pem)},
    )


def _precheck(client: TestClient, precheck: dict, fingerprint: dict):
    plaintext = {
        "client_time": 1717834512000,
        **DEMO_SITE_CONTEXT,
        "fingerprint": fingerprint,
    }
    return client.post(
        "/api/captcha/precheck",
        json={
            "precheck_token": precheck["precheck_token"],
            **DEMO_SITE_CONTEXT,
            "payload": _encrypt_payload(plaintext, precheck["rsa_public_key"]),
        },
    )


def test_precheck_low_risk_returns_silent_pass() -> None:
    client = TestClient(app)
    precheck_key = _make_precheck_key(client)

    response = _precheck(client, precheck_key, _clean_fingerprint())
    body = response.json()

    assert response.status_code == 200
    assert body["code"] == 200
    assert body["data"]["action"] == "pass"
    assert body["data"]["captcha_type"] == CaptchaType.SILENT
    assert body["data"]["verify_signature"].startswith("vsig_")
    assert body["data"]["challenge"] is None
    assert body["data"]["reason"] == "clean_environment"

    replay = _precheck(client, precheck_key, _clean_fingerprint())
    assert replay.json()["data"]["reason"] == "precheck_expired_or_not_found"


def test_precheck_key_requires_configured_site_key() -> None:
    client = TestClient(app)

    missing = client.get("/api/captcha/precheck-key")
    assert missing.json()["code"] == 403
    assert missing.json()["msg"] == "invalid_site_key"

    unknown = client.get(
        "/api/captcha/precheck-key",
        params={"site_key": "vsec_site_missing", "action": "login", "hostname": "localhost"},
    )
    assert unknown.json()["code"] == 403
    assert unknown.json()["msg"] == "invalid_site_key"


def test_precheck_medium_risk_returns_click_checkbox_type() -> None:
    client = TestClient(app)
    precheck_key = _make_precheck_key(client)
    fingerprint = _clean_fingerprint()
    fingerprint["canvas_id"] = "canvas-unavailable"

    response = _precheck(client, precheck_key, fingerprint)
    body = response.json()

    assert response.status_code == 200
    assert body["code"] == 200
    assert body["msg"] == "checkbox_required"
    assert body["data"]["action"] == "challenge"
    assert body["data"]["captcha_type"] == CaptchaType.CLICK_CHECKBOX
    assert body["data"]["verify_signature"] is None
    assert body["data"]["challenge"]["captcha_type"] == CaptchaType.CLICK_CHECKBOX
    assert body["data"]["challenge"]["captcha_token"].startswith("cbx_rsa_")
    assert "BEGIN PUBLIC KEY" in body["data"]["challenge"]["rsa_public_key"]
    assert body["data"]["reason"] == "weak_browser_fingerprint"


def test_verify_checkbox_success_issues_signature() -> None:
    client = TestClient(app)
    precheck_key = _make_precheck_key(client)
    fingerprint = _clean_fingerprint()
    fingerprint["canvas_id"] = "canvas-unavailable"
    response = _precheck(client, precheck_key, fingerprint)
    challenge = response.json()["data"]["challenge"]

    plaintext = _checkbox_plaintext(challenge["captcha_token"])
    verify_response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    body = verify_response.json()

    assert verify_response.status_code == 200
    assert body["code"] == 200
    assert body["data"]["verify_signature"].startswith("vsig_")
    assert session_store.get(challenge["captcha_token"]) is None


def test_verify_checkbox_rejects_uniform_motion_tracks() -> None:
    client = TestClient(app)
    precheck_key = _make_precheck_key(client)
    fingerprint = _clean_fingerprint()
    fingerprint["canvas_id"] = "canvas-unavailable"
    response = _precheck(client, precheck_key, fingerprint)
    challenge = response.json()["data"]["challenge"]
    uniform_tracks = [[index * 4, index * 4, index * 10, 0] for index in range(1, 10)]

    plaintext = _checkbox_plaintext(challenge["captcha_token"], uniform_tracks)
    verify_response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)

    assert verify_response.json()["data"]["reason"] == "static_uniform_motion_detected"


def test_precheck_high_risk_returns_slider_challenge() -> None:
    client = TestClient(app)
    precheck_key = _make_precheck_key(client)
    fingerprint = _clean_fingerprint()
    fingerprint["fake_webdriver"] = True
    fingerprint["webdriver"] = True
    fingerprint["probe_notes"] = ["fake webdriver injected by test"]

    response = _precheck(client, precheck_key, fingerprint)
    body = response.json()

    assert response.status_code == 200
    assert body["code"] == 200
    assert body["msg"] == "slider_required"
    assert body["data"]["action"] == "challenge"
    assert body["data"]["captcha_type"] == CaptchaType.SLIDER
    assert body["data"]["verify_signature"] is None
    assert body["data"]["reason"] == "automation_probe_detected"

    challenge = body["data"]["challenge"]
    assert challenge["captcha_type"] == CaptchaType.SLIDER
    assert challenge["captcha_token"].startswith("sess_rsa_")
    assert challenge["bg_image"].startswith("data:image/jpeg;base64,")
    assert challenge["slider_piece_b64"].startswith("data:image/png;base64,")
    assert "target_x" not in challenge
    assert "BEGIN PUBLIC KEY" in challenge["rsa_public_key"]

    session = session_store.get(challenge["captcha_token"])
    assert session is not None
    assert session.slider_answer is not None
    assert session.slider_answer.target_x > 100


def test_verify_slider_success_issues_signature_and_prevents_replay() -> None:
    client = TestClient(app)
    challenge, session = _make_challenge(client)
    target_x = session.slider_answer.target_x
    plaintext = _slider_plaintext(challenge["captcha_token"], target_x)

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    body = response.json()
    assert response.status_code == 200
    assert body["code"] == 200
    assert body["data"]["verify_signature"].startswith("vsig_")
    assert body["data"]["expires_in"] == 60
    assert body["data"]["risk_score"] < 0.65
    assert session_store.get(challenge["captcha_token"]) is None
    assert session_store.get_verify_signature(body["data"]["verify_signature"]) is not None

    replay = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    assert replay.json()["data"]["reason"] == "challenge_expired_or_not_found"


def test_siteverify_accepts_signature_and_consumes_it() -> None:
    client = TestClient(app)
    challenge, session = _make_challenge(client)
    plaintext = _slider_plaintext(challenge["captcha_token"], session.slider_answer.target_x)
    verify_response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    signature = verify_response.json()["data"]["verify_signature"]

    response = client.post(
        "/api/siteverify",
        json={
            "secret": DEFAULT_DEMO_SECRET,
            "response": signature,
            "action": DEMO_SITE_CONTEXT["action"],
            "hostname": DEMO_SITE_CONTEXT["hostname"],
        },
    )
    body = response.json()

    assert response.status_code == 200
    assert body["success"] is True
    assert body["action"] == DEMO_SITE_CONTEXT["action"]
    assert body["hostname"] == DEMO_SITE_CONTEXT["hostname"]
    assert body["error_codes"] == []
    assert session_store.get_verify_signature(signature) is None

    replay = client.post(
        "/api/siteverify",
        json={"secret": DEFAULT_DEMO_SECRET, "response": signature},
    )
    assert replay.json()["success"] is False
    assert replay.json()["error_codes"] == ["invalid-or-timeout-response"]


def test_siteverify_rejects_wrong_secret_action_and_hostname() -> None:
    client = TestClient(app)

    wrong_secret = client.post(
        "/api/siteverify",
        json={"secret": "wrong-secret", "response": "vsig_missing"},
    )
    assert wrong_secret.json()["error_codes"] == ["invalid-input-secret"]

    challenge, session = _make_challenge(client)
    plaintext = _slider_plaintext(challenge["captcha_token"], session.slider_answer.target_x)
    verify_response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    signature = verify_response.json()["data"]["verify_signature"]

    action_mismatch = client.post(
        "/api/siteverify",
        json={"secret": DEFAULT_DEMO_SECRET, "response": signature, "action": "checkout"},
    )
    assert action_mismatch.json()["success"] is False
    assert action_mismatch.json()["error_codes"] == ["action-mismatch"]

    challenge, session = _make_challenge(client)
    plaintext = _slider_plaintext(challenge["captcha_token"], session.slider_answer.target_x)
    verify_response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    signature = verify_response.json()["data"]["verify_signature"]

    hostname_mismatch = client.post(
        "/api/siteverify",
        json={"secret": DEFAULT_DEMO_SECRET, "response": signature, "hostname": "evil.example"},
    )
    assert hostname_mismatch.json()["success"] is False
    assert hostname_mismatch.json()["error_codes"] == ["hostname-mismatch"]


def test_verify_rejects_slider_when_overlap_below_relaxed_threshold() -> None:
    client = TestClient(app)
    challenge, session = _make_challenge(client)
    wrong_x = session.slider_answer.target_x - 20
    plaintext = _slider_plaintext(challenge["captcha_token"], wrong_x)

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    body = response.json()
    assert body["data"]["reason"] == "slider_overlap_ratio_too_low"
    assert body["data"]["features"]["overlap_ratio"] < 0.70


def test_verify_accepts_low_risk_human_slider_with_relaxed_overlap() -> None:
    client = TestClient(app)
    challenge, session = _make_challenge(client)
    near_x = session.slider_answer.target_x + 15
    plaintext = _slider_plaintext(challenge["captcha_token"], near_x)

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    body = response.json()

    assert body["code"] == 200
    assert body["data"]["verify_signature"].startswith("vsig_")
    assert body["data"]["features"]["overlap_ratio"] >= 0.70
    assert body["data"]["features"]["required_overlap"] == 0.70


def test_verify_rejects_payload_captcha_type_mismatch() -> None:
    client = TestClient(app)
    challenge, session = _make_challenge(client)
    plaintext = _slider_plaintext(challenge["captcha_token"], session.slider_answer.target_x)
    plaintext["captcha_type"] = CaptchaType.CLICK_CHECKBOX
    plaintext["checkbox_checked"] = True

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)

    assert response.json()["data"]["reason"] == "captcha_type_mismatch"


def test_verify_rejects_automation_probe_uniform_motion_and_teleportation() -> None:
    client = TestClient(app)
    challenge, session = _make_challenge(client)
    target_x = session.slider_answer.target_x
    plaintext = _slider_plaintext(challenge["captcha_token"], target_x)
    plaintext["fingerprint"]["webdriver"] = True

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    assert response.json()["data"]["reason"] == "automation_probe_detected"

    challenge, session = _make_challenge(client)
    target_x = session.slider_answer.target_x
    uniform_tracks = [[index * 5, 136, index * 10, 0] for index in range(1, 12)]
    plaintext = _slider_plaintext(challenge["captcha_token"], target_x, uniform_tracks)

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    assert response.json()["data"]["reason"] == "static_uniform_motion_detected"

    challenge, session = _make_challenge(client)
    target_x = session.slider_answer.target_x
    teleport_tracks = [
        [0, 136, 0, 1],
        [5000, 136, 10, 0],
        [5010, 136, 40, 0],
        [5022, 136, 75, 0],
        [target_x, 136, 120, 2],
    ]
    plaintext = _slider_plaintext(challenge["captcha_token"], target_x, teleport_tracks)

    response = _verify(client, challenge["captcha_token"], challenge["rsa_public_key"], plaintext)
    assert response.json()["data"]["reason"] == "teleportation_detected"


def test_verify_handles_decrypt_failure_without_crashing() -> None:
    client = TestClient(app)
    challenge, _session = _make_challenge(client)
    response = client.post(
        "/api/captcha/verify",
        json={
            "captcha_token": challenge["captcha_token"],
            "payload": {
                "encrypted_key": "bad",
                "encrypted_payload": {"iv": "bad", "ciphertext": "bad"},
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["code"] == 403
    assert response.json()["data"]["reason"] == "payload_decrypt_failed"


def test_verify_rate_limits_same_ip_after_fifteen_requests() -> None:
    client = TestClient(app)

    for _index in range(15):
        response = client.post(
            "/api/captcha/verify",
            json={"captcha_token": "missing-token", "payload": {}},
        )
        assert response.status_code == 200
        assert response.json()["data"]["reason"] == "challenge_expired_or_not_found"

    response = client.post(
        "/api/captcha/verify",
        json={"captcha_token": "missing-token", "payload": {}},
    )

    assert response.status_code == 429
    assert response.json()["data"]["reason"] == "rate_limited"
