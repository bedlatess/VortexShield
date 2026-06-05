from fastapi.testclient import TestClient

from app.main import app
from app.services.site_registry import DEFAULT_DEMO_SITE_KEY


def _login_admin(client: TestClient) -> None:
    response = client.post(
        "/home/admin/api/login",
        json={"admin_token": "vsec_admin_demo"},
    )
    assert response.status_code == 200
    assert response.json()["code"] == 200
    assert "vsec_admin_session" in response.cookies


def test_admin_panel_requires_cookie_session() -> None:
    client = TestClient(app)

    page = client.get("/home/admin", follow_redirects=False)
    api = client.get("/home/admin/api/sites")

    assert page.status_code == 302
    assert page.headers["location"] == "/home/admin/login"
    assert api.status_code == 403
    assert api.json()["msg"] == "admin_token_required"


def test_admin_login_page_and_cookie_login() -> None:
    client = TestClient(app)

    login_page = client.get("/home/admin/login")
    assert login_page.status_code == 200
    assert "项目管理员控制入口" in login_page.text

    rejected = client.post(
        "/home/admin/api/login",
        json={"admin_token": "wrong"},
    )
    assert rejected.status_code == 403

    _login_admin(client)

    console = client.get("/home/admin")
    assert console.status_code == 200
    assert "VortexShield 控制面板" in console.text


def test_admin_can_disable_enable_rotate_and_delete_site() -> None:
    client = TestClient(app)
    _login_admin(client)

    created = client.post(
        "/home/api/sites",
        json={
            "allowed_domains": ["ops.example"],
            "allowed_actions": ["login"],
            "admin_token": "vsec_admin_demo",
        },
    )
    site_key = created.json()["data"]["site_key"]
    old_secret = created.json()["data"]["secret"]

    disabled = client.post(f"/home/admin/api/sites/{site_key}/disable")
    assert disabled.status_code == 200
    assert disabled.json()["data"]["enabled"] is False

    precheck_disabled = client.get(
        "/api/captcha/precheck-key",
        params={"site_key": site_key, "action": "login", "hostname": "ops.example"},
    )
    assert precheck_disabled.json()["msg"] == "site_disabled"

    enabled = client.post(f"/home/admin/api/sites/{site_key}/enable")
    assert enabled.status_code == 200
    assert enabled.json()["data"]["enabled"] is True

    rotated = client.post(f"/home/admin/api/sites/{site_key}/rotate-secret")
    assert rotated.status_code == 200
    new_secret = rotated.json()["data"]["secret"]
    assert new_secret.startswith("vsec_secret_")
    assert new_secret != old_secret

    deleted = client.delete(f"/home/admin/api/sites/{site_key}")
    assert deleted.status_code == 200
    assert deleted.json()["data"]["site_key"] == site_key

    precheck_deleted = client.get(
        "/api/captcha/precheck-key",
        params={"site_key": site_key, "action": "login", "hostname": "ops.example"},
    )
    assert precheck_deleted.json()["msg"] == "invalid_site_key"


def test_admin_cannot_delete_demo_site() -> None:
    client = TestClient(app)
    _login_admin(client)

    response = client.delete(f"/home/admin/api/sites/{DEFAULT_DEMO_SITE_KEY}")

    assert response.status_code == 400
    assert response.json()["msg"] == "demo_site_cannot_be_deleted"

