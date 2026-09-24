import pytest

from app import create_app
from app.cloud import cloud_config


def test_cloud_requires_explicit_demo(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("CLOUD_DEMO", raising=False)
    with pytest.raises(RuntimeError, match="CLOUD_DEMO"):
        cloud_config()


def test_cloud_requires_private_secret(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("CLOUD_DEMO", "true")
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        cloud_config()


def test_cloud_login_and_discovery(monkeypatch, tmp_path):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("CLOUD_DEMO", "true")
    monkeypatch.setenv("SECRET_KEY", "cloud-test-secret-" * 4)
    monkeypatch.setenv("DEMO_ADMIN_USERNAME", "cloud-demo")
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "Cloud-test-passphrase!")
    monkeypatch.setenv("ENABLE_LIVE_SCAN", "true")
    monkeypatch.setattr("app.cloud.tempfile.mkdtemp", lambda **kwargs: str(tmp_path))
    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
    assert app.instance_path == str(tmp_path)
    assert app.config["ENABLE_LIVE_SCAN"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is True
    client = app.test_client()
    assert b"TEMPORARY CLOUD DEMO" in client.get("/login").data
    response = client.post(
        "/login", data={"username": "cloud-demo", "password": "Cloud-test-passphrase!"}
    )
    assert response.status_code == 302
    assert client.get("/").status_code == 200
    response = client.post("/api/scans", json={"mode": "demo", "authorized": True})
    assert response.status_code == 201
    assert b"synthetic networks" in client.get("/").data
    with app.app_context():
        from app.extensions import db

        db.session.remove()
        db.engine.dispose()
