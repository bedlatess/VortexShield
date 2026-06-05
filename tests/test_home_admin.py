from fastapi.testclient import TestClient

from app.main import app


def test_home_pages_render_without_conflicting_with_api_routes() -> None:
    client = TestClient(app)

    home = client.get("/home")
    console = client.get("/home/api")
    health = client.get("/health")

    assert home.status_code == 200
    assert "VortexShield" in home.text
    assert console.status_code == 200
    assert "Access Console" in console.text
    assert "接入凭证中心" in console.text
    assert health.json() == {"status": "ok"}


def test_admin_can_create_site_api_and_use_site_key() -> None:
    client = TestClient(app)

    rejected = client.post(
        "/home/api/sites",
        json={
            "allowed_domains": ["example.com"],
            "allowed_actions": ["login"],
            "admin_token": "wrong",
        },
    )
    assert rejected.status_code == 403
    assert rejected.json()["msg"] == "admin_token_required"

    created = client.post(
        "/home/api/sites",
        json={
            "allowed_domains": ["example.com"],
            "allowed_actions": ["login"],
            "admin_token": "vsec_admin_demo",
        },
    )
    body = created.json()
    assert created.status_code == 200
    assert body["code"] == 200
    assert body["data"]["site_key"].startswith("vsec_site_")
    assert body["data"]["secret"].startswith("vsec_secret_")
    assert body["data"]["allowed_domains"] == ["example.com"]

    precheck_key = client.get(
        "/api/captcha/precheck-key",
        params={
            "site_key": body["data"]["site_key"],
            "action": "login",
            "hostname": "example.com",
        },
    )
    assert precheck_key.status_code == 200
    assert precheck_key.json()["code"] == 200
    assert precheck_key.json()["data"]["precheck_token"].startswith("pre_rsa_")

    sites = client.get("/home/api/sites", headers={"X-VSEC-Admin-Token": "vsec_admin_demo"})
    site_keys = [site["site_key"] for site in sites.json()["data"]]
    assert body["data"]["site_key"] in site_keys
