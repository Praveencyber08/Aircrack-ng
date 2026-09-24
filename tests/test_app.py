import io

import pytest
from pypdf import PdfReader
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Assessment, AuditLog, Finding, Network, Scan, User


def test_authentication_and_logout(client, app):
    assert client.get("/api/networks").status_code == 401
    assert client.get("/").status_code == 302
    assert client.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 401
    assert (
        client.post(
            "/login", data={"username": "admin", "password": "Testing-only-passphrase!"}
        ).status_code
        == 302
    )
    assert client.get("/").status_code == 200
    assert client.post("/logout").status_code == 302
    assert client.get("/api/networks").status_code == 401
    with app.app_context():
        user = db.session.scalar(db.select(User).where(User.username == "admin"))
        assert user.password_hash != "Testing-only-passphrase!"
        assert user.password_hash.startswith("scrypt:")
        assert "Testing-only" not in " ".join(
            x.detail for x in db.session.scalars(db.select(AuditLog))
        )


@pytest.mark.parametrize("url", ["/users", "/settings", "/audit-logs", "/api/audit-logs"])
def test_analyst_cannot_admin(client, url):
    client.post("/login", data={"username": "analyst", "password": "Testing-only-passphrase!"})
    assert client.get(url).status_code == 403


def test_analyst_can_assess(client):
    client.post("/login", data={"username": "analyst", "password": "Testing-only-passphrase!"})
    assert client.post("/api/scans", json={"authorized": True}).status_code == 201
    assert (
        client.post("/api/assessments", json={"network_id": 1, "authorized": True}).status_code
        == 201
    )


def test_demo_pipeline_and_snapshot(seeded, app):
    result = seeded.get("/api/networks").json
    assert result["total"] == 4
    assert {n["essid"] for n in result["items"]} == {"LAB-WIFI", "LAB-WPA2", "LAB-WPA3", "LAB-OPEN"}
    assert all(n["demo"] and n["authorized"] for n in result["items"])
    assert b"DEMO DATA" in seeded.get("/").data
    assert seeded.post("/api/scans", json={"mode": "demo", "authorized": True}).status_code == 201
    assert seeded.get("/api/networks").json["total"] == 4
    assert len(seeded.get("/api/networks/1").json["history"]) == 2
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(Assessment.id))) == 8
        assert (
            db.session.scalar(db.select(db.func.count(Finding.id)).where(Finding.current.is_(True)))
            == 4
        )


@pytest.mark.parametrize(
    "page",
    [
        "/",
        "/interfaces",
        "/discovery",
        "/networks",
        "/networks/1",
        "/findings",
        "/captures",
        "/reports",
        "/audit-logs",
        "/users",
        "/settings",
        "/change-password",
        "/compare?id=1&id=2",
    ],
)
def test_pages_render(seeded, page):
    response = seeded.get(page)
    assert response.status_code == 200, response.data[:1000]
    assert b"SPECTRA" in response.data


def test_filters_pagination_and_injection(seeded):
    assert seeded.get("/api/networks?q=LAB-WPA&per_page=1").json["total"] == 2
    assert len(seeded.get("/api/networks?per_page=1&page=2").json["items"]) == 1
    assert seeded.get("/api/networks?encryption=WPA2").json["total"] == 1
    assert seeded.get("/api/networks?severity=Critical").json["total"] == 1
    assert seeded.get("/api/networks?channel=36").json["items"][0]["essid"] == "LAB-WPA3"
    assert seeded.get("/api/networks?q=%27%20OR%201=1--").json["total"] == 0
    assert seeded.get("/api/networks?q=%25").json["total"] == 0
    assert seeded.get("/api/networks?page=-1").status_code == 400
    assert seeded.get("/api/networks?date=nonsense").status_code == 400
    assert seeded.get("/api/networks?severity=catastrophic").status_code == 400
    assert seeded.get("/compare?id=1").status_code == 400


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"authorized": False},
        {"authorized": "yes"},
        {"authorized": True, "mode": "bad"},
        {"authorized": True, "duration": ";whoami"},
        [],
    ],
)
def test_scan_validation(signed, body):
    assert signed.post("/api/scans", json=body).status_code == 400


def test_scope_and_live_gates(seeded, app):
    assert seeded.post("/api/scans", json={"mode": "live", "authorized": True}).status_code == 400
    with app.app_context():
        db.session.add(
            Network(essid="unapproved", bssid="02:11:22:33:44:55", encryption="WPA2", demo=False)
        )
        db.session.commit()
    assert (
        seeded.post("/api/assessments", json={"network_id": 5, "authorized": True}).status_code
        == 403
    )
    assert (
        seeded.post("/api/reports/generate", json={"network_id": 5, "authorized": True}).status_code
        == 403
    )
    app.config["DEMO_MODE"] = False
    assert seeded.post("/api/scans", json={"authorized": True}).status_code == 400
    assert (
        seeded.post("/api/assessments", json={"network_id": 1, "authorized": True}).status_code
        == 403
    )


def test_report_download_and_preserved_snapshot(seeded, app):
    response = seeded.post("/api/reports/generate", json={"network_id": 1, "authorized": True})
    assert response.status_code == 201, response.json
    download = seeded.get(response.json["download_url"])
    assert download.status_code == 200
    assert download.data.startswith(b"%PDF")
    reader = PdfReader(io.BytesIO(download.data))
    text = "\n".join(page.extract_text() for page in reader.pages)
    for required in (
        "Executive summary",
        "DEMO DATA",
        "WEP",
        "Recommendation",
        "Conclusion",
        "Authorization".lower(),
    ):
        assert required.lower() in text.lower()
    assert len(reader.pages) >= 3
    with app.app_context():
        db.session.get(Network, 1).essid = "changed"
        db.session.commit()
    assert seeded.get(response.json["download_url"]).data == download.data
    anon = app.test_client()
    assert anon.get(response.json["download_url"]).status_code == 302


def test_password_rotation_and_deleted_user(signed, app):
    second = app.test_client()
    second.post("/login", data={"username": "admin", "password": "Testing-only-passphrase!"})
    assert (
        signed.post(
            "/change-password",
            data={
                "current_password": "Testing-only-passphrase!",
                "new_password": "A-new-test-password-123",
            },
        ).status_code
        == 302
    )
    assert second.get("/api/networks").status_code == 401
    assert signed.get("/").status_code == 200
    assert signed.post("/users/1/delete").status_code == 400
    analyst = app.test_client()
    analyst.post("/login", data={"username": "analyst", "password": "Testing-only-passphrase!"})
    assert signed.post("/users/2/delete").status_code == 302
    assert analyst.get("/api/networks").status_code == 401


def test_settings_users_and_scope(signed, app):
    assert (
        signed.post(
            "/users",
            data={
                "username": "new-analyst",
                "password": "Strong-test-password!",
                "role": "analyst",
            },
        ).status_code
        == 302
    )
    assert (
        signed.post(
            "/users", data={"username": "invalid!", "password": "x", "role": "root"}
        ).status_code
        == 400
    )
    data = {
        "action": "scope",
        "bssid": "02:11:22:33:44:55",
        "channel": "6",
        "label": "Owned lab",
        "permission_reference": "Signed lab authorization 001",
    }
    assert signed.post("/settings", data=data).status_code == 302
    assert signed.post("/settings", data=data).status_code == 400
    assert signed.post("/scopes/1/delete").status_code == 302
    assert (
        signed.post(
            "/settings",
            data={
                "action": "rules",
                "open": "Medium",
                "wep": "High",
                "wpa": "High",
                "tkip": "Low",
                "unknown": "Low",
            },
        ).status_code
        == 302
    )
    assert signed.post("/api/scans", json={"authorized": True}).status_code == 201
    assert signed.get("/api/networks/1").json["findings"][0]["severity"] == "High"


def test_database_foreign_keys_and_uniqueness(app):
    with app.app_context():
        db.session.add(Scan(user_id=999, mode="demo", authorized=True))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        db.session.add(User(username="admin", password_hash="x", role="admin"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_csrf_and_headers(app):
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()
    assert (
        client.post(
            "/login", data={"username": "admin", "password": "Testing-only-passphrase!"}
        ).status_code
        == 400
    )
    import re

    response = client.get("/login")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()
    assert (
        client.post(
            "/login",
            data={"csrf_token": token, "username": "admin", "password": "Testing-only-passphrase!"},
        ).status_code
        == 302
    )
    assert client.post("/api/scans", json={"authorized": True}).status_code == 400
    token = client.get("/api/csrf-token").json["csrf_token"]
    assert (
        client.post(
            "/api/scans", json={"authorized": True}, headers={"X-CSRFToken": token}
        ).status_code
        == 201
    )
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]


def test_xss_escaped(seeded, app):
    with app.app_context():
        db.session.get(Network, 1).essid = '<script>alert("x")</script>'
        db.session.commit()
    response = seeded.get("/networks/1")
    assert b"<script>alert" not in response.data
    assert b"&lt;script&gt;" in response.data


def test_missing_and_error_routes(signed):
    assert signed.get("/api/networks/999").status_code == 404
    assert signed.get("/reports/999/download").status_code == 404
    assert signed.get("/api/findings?severity=bad").status_code == 400
    assert signed.get("/api/reports").status_code == 200
    assert signed.get("/api/scans").status_code == 200
    assert signed.get("/api/audit-logs").status_code == 200
    assert signed.get("/api/interfaces").status_code == 200
