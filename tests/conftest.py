import pytest

from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-only-" * 4,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": False,
            "DEMO_MODE": True,
            "ENABLE_LIVE_SCAN": False,
            "UPLOAD_DIR": str(tmp_path / "uploads"),
            "REPORT_DIR": str(tmp_path / "reports"),
        }
    )
    with application.app_context():
        db.create_all()
        for name, role in [("admin", "admin"), ("analyst", "analyst")]:
            user = User(username=name, role=role)
            user.set_password("Testing-only-passphrase!")
            db.session.add(user)
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def signed(client):
    response = client.post(
        "/login", data={"username": "admin", "password": "Testing-only-passphrase!"}
    )
    assert response.status_code == 302
    return client


@pytest.fixture
def seeded(signed):
    response = signed.post("/api/scans", json={"mode": "demo", "authorized": True})
    assert response.status_code == 201, response.json
    return signed
