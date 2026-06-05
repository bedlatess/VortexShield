import base64
import io

from fastapi.testclient import TestClient
from PIL import Image

from app.core.enums import CaptchaType
from app.main import app
from app.services.captcha_generator import generate_slider_challenge
from app.services.session_store import session_store


DEMO_SITE_CONTEXT = {
    "site_key": "vsec_site_demo",
    "action": "login",
    "hostname": "localhost",
}


def _decode_data_uri(data_uri: str) -> Image.Image:
    _prefix, raw = data_uri.split(",", 1)
    return Image.open(io.BytesIO(base64.b64decode(raw)))


def test_generate_slider_challenge_returns_background_piece_and_private_answer() -> None:
    challenge = generate_slider_challenge()

    assert challenge.bg_image.startswith("data:image/jpeg;base64,")
    assert challenge.slider_piece_b64.startswith("data:image/png;base64,")
    assert challenge.width == 320
    assert challenge.height == 160
    assert challenge.target_x > 100
    assert 0 <= challenge.target_y <= challenge.height - challenge.piece_height
    assert challenge.shape in {"square", "star", "moon"}

    bg_image = _decode_data_uri(challenge.bg_image)
    piece = _decode_data_uri(challenge.slider_piece_b64)

    assert bg_image.size == (challenge.width, challenge.height)
    assert piece.size == (challenge.piece_width, challenge.piece_height)
    assert piece.mode == "RGBA"

    alpha = piece.getchannel("A")
    assert alpha.getbbox() is not None
    assert alpha.getextrema()[1] > 0


def test_challenge_api_returns_slider_contract_and_stores_target_x_privately() -> None:
    client = TestClient(app)
    response = client.get("/api/captcha/challenge", params=DEMO_SITE_CONTEXT)

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 200
    assert body["msg"] == "success"

    data = body["data"]
    assert data["captcha_token"].startswith("sess_rsa_")
    assert data["captcha_type"] == CaptchaType.SLIDER
    assert data["bg_image"].startswith("data:image/jpeg;base64,")
    assert data["slider_piece_b64"].startswith("data:image/png;base64,")
    assert data["dimensions"] == {"width": 320, "height": 160}
    assert data["piece_size"]["width"] > 0
    assert data["piece_size"]["height"] > 0
    assert data["initial_x"] == 0
    assert 0 <= data["piece_y"] <= data["dimensions"]["height"] - data["piece_size"]["height"]
    assert "BEGIN PUBLIC KEY" in data["rsa_public_key"]
    assert "target_x" not in data

    session = session_store.get(data["captcha_token"])
    assert session is not None
    assert session.captcha_type == CaptchaType.SLIDER
    assert session.slider_answer is not None
    assert session.slider_answer.target_x > 100
    assert "BEGIN PRIVATE KEY" in session.rsa_private_key_pem


def test_challenge_api_rejects_missing_site_key() -> None:
    client = TestClient(app)
    response = client.get("/api/captcha/challenge")

    assert response.status_code == 403
    assert response.json()["msg"] == "invalid_site_key"
