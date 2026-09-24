"""Application operations shared by web forms and REST endpoints."""

import hashlib
import json
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from flask import abort, current_app
from flask_login import current_user
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import (
    Assessment,
    Capture,
    Finding,
    Network,
    Observation,
    Report,
    Scan,
    Scope,
    Setting,
    WirelessInterface,
    utcnow,
)
from app.security import audit, confirmed, integer, mac
from app.services.risk import DEFAULT_RULES, assess
from scanners.aircrack_wrapper import AircrackWrapper, ToolError, interface_name
from scanners.interface_detector import detect_interfaces
from scanners.wifi_scanner import parse_csv

DEMO_NETWORKS = [
    dict(
        essid="LAB-WIFI",
        bssid="02:00:00:00:00:01",
        channel=1,
        encryption="WEP",
        cipher="WEP",
        authentication="OPN",
        signal=-67,
        stations=[],
    ),
    dict(
        essid="LAB-WPA2",
        bssid="02:00:00:00:00:02",
        channel=6,
        encryption="WPA2",
        cipher="CCMP",
        authentication="PSK",
        signal=-42,
        stations=["02:00:00:01:00:02"],
    ),
    dict(
        essid="LAB-WPA3",
        bssid="02:00:00:00:00:03",
        channel=36,
        encryption="WPA3",
        cipher="CCMP",
        authentication="SAE",
        signal=-51,
        stations=[],
    ),
    dict(
        essid="LAB-OPEN",
        bssid="02:00:00:00:00:04",
        channel=11,
        encryption="OPN",
        cipher="",
        authentication="OPN",
        signal=-73,
        stations=[],
    ),
]


def network_facts(network):
    return {
        key: getattr(network, key)
        for key in (
            "essid",
            "bssid",
            "channel",
            "encryption",
            "cipher",
            "authentication",
            "signal",
            "demo",
        )
    }


def allowed(network):
    if network.demo:
        return bool(current_app.config["DEMO_MODE"])
    return db.session.scalar(db.select(Scope).filter_by(bssid=network.bssid)) is not None


def get_network(value, require_scope=False):
    network = db.get_or_404(Network, integer(value, "Network ID"))
    if require_scope and not allowed(network):
        abort(403, "Network is outside the current approved scope.")
    return network


def rules():
    setting = db.session.get(Setting, "risk_rules")
    return {**DEFAULT_RULES, **(setting.value if setting else {})}


def assessment(network, authorized=True):
    scope = db.session.scalar(db.select(Scope).filter_by(bssid=network.bssid))
    snapshot = network_facts(network)
    snapshot["last_seen"] = network.last_seen.isoformat()
    record = Assessment(
        network=network,
        user_id=current_user.id,
        authorized=authorized,
        scope_reference="Synthetic laboratory data" if network.demo else scope.permission_reference,
        evidence=snapshot,
        rules=rules(),
    )
    db.session.add(record)
    for finding in network.findings:
        finding.current = False
    for item in assess(snapshot, record.rules):
        db.session.add(Finding(network=network, assessment=record, **item))
    audit("assessment_started", f"Network {network.id}; explicit authorization recorded")
    db.session.flush()
    return record


def start_assessment(data):
    confirmed(data)
    network = get_network(data.get("network_id"), require_scope=True)
    result = assessment(network)
    db.session.commit()
    return result


def refresh_interfaces():
    detected = detect_interfaces()
    db.session.execute(db.delete(WirelessInterface))
    for item in detected:
        db.session.add(WirelessInterface(**item))
    db.session.commit()
    return detected


def start_scan(data):
    confirmed(data)
    mode = data.get("mode", "demo")
    if mode not in ("demo", "live"):
        raise ValueError("Mode must be demo or live.")
    if mode == "demo" and not current_app.config["DEMO_MODE"]:
        raise ValueError("Demo mode is disabled.")
    duration = integer(data.get("duration", 10), "Duration", 5, 60)
    scope, interface = None, None
    if mode == "live":
        if not current_app.config["ENABLE_LIVE_SCAN"]:
            raise ValueError("Live scanning is disabled in server configuration.")
        scope = db.session.scalar(db.select(Scope).filter_by(bssid=mac(data.get("bssid"))))
        if not scope:
            abort(403, "BSSID is outside the approved lab scope.")
        interface = interface_name(data.get("interface"))
        devices = detect_interfaces()
        if not any(d["name"] == interface and d["mode"] == "monitor" for d in devices):
            raise ValueError("Select a detected interface already configured in monitor mode.")
    scan = Scan(
        user_id=current_user.id,
        mode=mode,
        interface=interface,
        scope_bssid=scope.bssid if scope else None,
        scope_reference=scope.permission_reference if scope else "Synthetic laboratory data",
        authorized=True,
    )
    db.session.add(scan)
    db.session.flush()
    audit(
        "scan_started", f"Scan {scan.id}; mode {mode}; scope {scan.scope_bssid or 'synthetic lab'}"
    )
    db.session.commit()
    try:
        if mode == "demo":
            items = DEMO_NETWORKS
        else:
            with tempfile.TemporaryDirectory(dir=current_app.config["UPLOAD_DIR"]) as directory:
                path = AircrackWrapper().passive_scan(
                    interface, scope.bssid, scope.channel, duration, directory
                )
                items = parse_csv(path, [scope.bssid])
        for item in items:
            network = db.session.scalar(
                db.select(Network).filter_by(bssid=item["bssid"], demo=mode == "demo")
            )
            if network is None:
                network = Network(bssid=item["bssid"], demo=mode == "demo")
                db.session.add(network)
            for key in (
                "essid",
                "channel",
                "encryption",
                "cipher",
                "authentication",
                "signal",
                "stations",
            ):
                setattr(network, key, item[key])
            network.last_seen = utcnow()
            if network.first_seen is None:
                network.first_seen = network.last_seen
            db.session.flush()
            db.session.add(Observation(network=network, scan=scan, facts=dict(item)))
            assessment(network)
        scan.network_count = len(items)
        scan.status = "completed"
        scan.completed_at = utcnow()
        audit("scan_completed", f"Scan {scan.id}; {len(items)} scoped networks")
        db.session.commit()
    except (ToolError, ValueError, OSError):
        db.session.rollback()
        scan = db.session.get(Scan, scan.id)
        scan.status = "failed"
        scan.completed_at = utcnow()
        scan.error = (
            "Scan failed; verify tools, adapter mode and permissions. No partial results saved."
        )
        audit("scan_failed", f"Scan {scan.id}")
        db.session.commit()
        raise ToolError(scan.error) from None
    return scan


def analyze_upload(data, upload):
    confirmed(data)
    network = get_network(data.get("network_id"), require_scope=True)
    if upload is None or not upload.filename:
        raise ValueError("Choose a capture file.")
    original = upload.filename
    if (
        len(original) > 180
        or any(c in original for c in ("/", "\\", "\x00"))
        or original.startswith(".")
    ):
        raise ValueError("Invalid upload filename.")
    filename = secure_filename(original)
    if Path(filename).suffix.lower() not in {".cap", ".pcap", ".pcapng"}:
        raise ValueError("Only .cap, .pcap and .pcapng files are supported.")
    with tempfile.TemporaryDirectory(dir=current_app.config["UPLOAD_DIR"]) as directory:
        path = Path(directory) / (uuid.uuid4().hex + Path(filename).suffix.lower())
        upload.save(path)
        size = path.stat().st_size
        if not 24 <= size <= current_app.config["MAX_CONTENT_LENGTH"]:
            raise ValueError("Capture is empty, truncated or oversized.")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        script = Path(current_app.root_path).parent / "scanners/packet_analyzer.py"
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    str(path),
                    network.bssid,
                    str(current_app.config["CAPTURE_PACKET_LIMIT"]),
                ],
                capture_output=True,
                text=True,
                timeout=current_app.config["CAPTURE_TIMEOUT"],
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError("Capture analysis exceeded the time limit.") from exc
        if result.returncode != 0:
            raise ValueError("Invalid, unsupported, out-of-scope or over-limit capture.")
        try:
            details = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ValueError("Capture analyzer returned an invalid result.") from exc
    record = Capture(
        user_id=current_user.id,
        filename=filename,
        size=size,
        sha256=digest,
        network_id=network.id,
        authorized=True,
        details=details,
    )
    db.session.add(record)
    audit("capture_uploaded", f"Metadata analyzed for network {network.id}; raw file deleted")
    db.session.commit()
    return record


def generate_report(data):
    from reports.report_generator import build_report

    confirmed(data)
    network = get_network(data.get("network_id"), require_scope=True)
    result = assessment(network)
    filename = uuid.uuid4().hex + ".pdf"
    path = Path(current_app.config["REPORT_DIR"]) / filename
    try:
        build_report(path, result, current_user.username)
        report = Report(
            user_id=current_user.id,
            network_id=network.id,
            assessment_id=result.id,
            filename=filename,
        )
        db.session.add(report)
        audit("report_generated", f"Network {network.id}; assessment {result.id}")
        db.session.commit()
        return report
    except Exception:
        db.session.rollback()
        path.unlink(missing_ok=True)
        raise
