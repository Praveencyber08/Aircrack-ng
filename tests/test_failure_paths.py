import io
import subprocess
from pathlib import Path
from unittest.mock import Mock

from app.extensions import db
from app.models import Scan
from scanners.aircrack_wrapper import ToolError


def approve(client):
    response = client.post(
        "/settings",
        data={
            "action": "scope",
            "label": "Owned lab",
            "bssid": "02:11:22:33:44:55",
            "channel": 6,
            "permission_reference": "Test authorization",
        },
    )
    assert response.status_code == 302


def test_live_scope_blocks_before_tool(signed, app, monkeypatch):
    app.config["ENABLE_LIVE_SCAN"] = True
    tool = Mock()
    monkeypatch.setattr("app.services.workflows.AircrackWrapper.passive_scan", tool)
    response = signed.post(
        "/api/scans",
        json={
            "authorized": True,
            "mode": "live",
            "bssid": "02:11:22:33:44:55",
            "interface": "wlan0mon",
        },
    )
    assert response.status_code == 403
    tool.assert_not_called()


def test_live_failure_records_status(signed, app, monkeypatch):
    approve(signed)
    app.config["ENABLE_LIVE_SCAN"] = True
    monkeypatch.setattr(
        "app.services.workflows.detect_interfaces",
        lambda: [{"name": "wlan0mon", "mode": "monitor"}],
    )
    monkeypatch.setattr(
        "app.services.workflows.AircrackWrapper.passive_scan",
        Mock(side_effect=ToolError("failure")),
    )
    response = signed.post(
        "/api/scans",
        json={
            "authorized": True,
            "mode": "live",
            "bssid": "02:11:22:33:44:55",
            "interface": "wlan0mon",
        },
    )
    assert response.status_code == 503
    with app.app_context():
        scan = db.session.scalar(db.select(Scan))
        assert scan.status == "failed"
        assert scan.completed_at is not None
    assert list(Path(app.config["UPLOAD_DIR"]).iterdir()) == []


def test_live_success_only_scoped_result(signed, app, monkeypatch):
    approve(signed)
    app.config["ENABLE_LIVE_SCAN"] = True
    monkeypatch.setattr(
        "app.services.workflows.detect_interfaces",
        lambda: [{"name": "wlan0mon", "mode": "monitor"}],
    )

    def fake_scan(self, interface, bssid, channel, duration, directory):
        path = Path(directory) / "observation-01.csv"
        path.write_text(
            "BSSID,First,Last,channel,Speed,Privacy,Cipher,Authentication,Power,beacons,IV,IP,ID-length,ESSID\n02:11:22:33:44:55,2026-09-24 10:00:00,2026-09-24 10:00:10,6,54,WPA2,CCMP,PSK,-50,1,0,0,3,LAB\n02:11:22:33:44:66,2026-09-24 10:00:00,2026-09-24 10:00:10,6,54,OPN,,,-40,1,0,0,5,OTHER\n"
        )
        return path

    monkeypatch.setattr("app.services.workflows.AircrackWrapper.passive_scan", fake_scan)
    response = signed.post(
        "/api/scans",
        json={
            "authorized": True,
            "mode": "live",
            "bssid": "02:11:22:33:44:55",
            "interface": "wlan0mon",
        },
    )
    assert response.status_code == 201
    assert response.json["network_count"] == 1
    network = signed.get("/api/networks").json["items"][0]
    assert network["demo"] is False
    assert network["first_seen"] <= network["last_seen"]
    assert network["essid"] == "LAB"
    signed.post("/scopes/1/delete")
    assert (
        signed.post(
            "/api/assessments", json={"network_id": network["id"], "authorized": True}
        ).status_code
        == 403
    )


def test_capture_timeout_cleanup(seeded, app, monkeypatch):
    monkeypatch.setattr(
        "app.services.workflows.subprocess.run",
        Mock(side_effect=subprocess.TimeoutExpired("parser", 30)),
    )
    response = seeded.post(
        "/api/captures/analyze",
        data={"network_id": 2, "authorized": "true", "file": (io.BytesIO(b"x" * 30), "test.pcap")},
    )
    assert response.status_code == 400
    assert "time limit" in response.json["error"]
    assert not list(Path(app.config["UPLOAD_DIR"]).iterdir())


def test_rate_limit(app):
    from app import create_app

    limited = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret" * 4,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": True,
            "REPORT_DIR": app.config["REPORT_DIR"],
            "UPLOAD_DIR": app.config["UPLOAD_DIR"],
        }
    )
    with limited.app_context():
        db.create_all()
    client = limited.test_client()
    responses = [
        client.post("/login", data={"username": "nobody", "password": "invalid"}) for _ in range(11)
    ]
    assert responses[-1].status_code == 429


def test_pdf_failure_rolls_back(seeded, app, monkeypatch):
    from app.models import Assessment, Report

    with app.app_context():
        before = db.session.scalar(db.select(db.func.count(Assessment.id)))
    monkeypatch.setattr(
        "reports.report_generator.build_report", Mock(side_effect=OSError("private system details"))
    )
    response = seeded.post("/api/reports/generate", json={"network_id": 1, "authorized": True})
    assert response.status_code == 500
    assert "private system details" not in response.get_data(as_text=True)
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(Report.id))) == 0
        assert db.session.scalar(db.select(db.func.count(Assessment.id))) == before
    assert not list(Path(app.config["REPORT_DIR"]).iterdir())
