import io
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL
from scapy.utils import PcapNgWriter, wrpcap

from app.services.risk import assess
from scanners.aircrack_wrapper import AircrackWrapper, ToolError, interface_name
from scanners.packet_analyzer import analyze
from scanners.wifi_scanner import parse_csv


def packets():
    beacon = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="02:00:00:00:00:02",
            addr3="02:00:00:00:00:02",
        )
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID="SSID", info=b"LAB-WPA2")
        / Dot11Elt(ID="DSset", info=b"\x06")
    )
    auth = RadioTap() / Dot11(
        type=2,
        subtype=0,
        FCfield=1,
        addr1="02:00:00:00:00:02",
        addr2="02:00:00:01:00:02",
        addr3="02:00:00:00:00:02",
    )
    from scapy.layers.l2 import LLC, SNAP

    return [
        beacon,
        auth
        / LLC(dsap=170, ssap=170, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=2, type=0),
    ]


@pytest.mark.parametrize("extension", ["pcap", "cap", "pcapng"])
def test_capture_formats_and_metadata(tmp_path, seeded, app, extension):
    path = tmp_path / ("lab." + extension)
    if extension == "pcapng":
        with PcapNgWriter(str(path)) as writer:
            for packet in packets():
                writer.write(packet)
    else:
        wrpcap(str(path), packets())
    response = seeded.post(
        "/api/captures/analyze",
        data={
            "network_id": "2",
            "authorized": "true",
            "file": (io.BytesIO(path.read_bytes()), path.name),
        },
    )
    assert response.status_code == 201, response.json
    metadata = response.json["metadata"]
    assert metadata["packet_count"] == 2
    assert metadata["channels"] == [6]
    assert metadata["eapol_frames"] == 1
    assert metadata["bssids"] == ["02:00:00:00:00:02"]
    assert list(Path(app.config["UPLOAD_DIR"]).iterdir()) == []
    assert seeded.get("/captures").status_code == 200


@pytest.mark.parametrize(
    "filename,data",
    [
        ("../evil.cap", b"x" * 30),
        ("..\\evil.cap", b"x" * 30),
        ("evil.exe", b"x" * 30),
        ("bad.pcap", b"not-a-pcap" * 4),
        ("empty.cap", b""),
    ],
)
def test_malicious_uploads(seeded, app, filename, data):
    response = seeded.post(
        "/api/captures/analyze",
        data={"network_id": "2", "authorized": "true", "file": (io.BytesIO(data), filename)},
    )
    assert response.status_code == 400
    assert not list(Path(app.config["UPLOAD_DIR"]).iterdir())


def test_upload_size_authorization_and_scope(seeded, app, tmp_path):
    assert seeded.post("/api/captures/analyze", data={"network_id": "2"}).status_code == 400
    path = tmp_path / "test.pcap"
    wrpcap(str(path), packets())
    assert (
        seeded.post(
            "/api/captures/analyze",
            data={
                "network_id": "1",
                "authorized": "true",
                "file": (io.BytesIO(path.read_bytes()), "lab.pcap"),
            },
        ).status_code
        == 400
    )
    app.config["MAX_CONTENT_LENGTH"] = 1024
    response = seeded.post(
        "/api/captures/analyze",
        data={
            "network_id": "2",
            "authorized": "true",
            "file": (io.BytesIO(b"x" * 2048), "lab.pcap"),
        },
    )
    assert response.status_code == 413


def test_truncated_and_over_limit_capture(tmp_path):
    path = tmp_path / "test.pcap"
    wrpcap(str(path), packets())
    with pytest.raises(ValueError, match="limit"):
        analyze(path, "02:00:00:00:00:02", packet_limit=1)
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError, match="length"):
        analyze(path, "02:00:00:00:00:02")


def test_wrapper_fixed_arguments_timeout_and_error(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    run = Mock(return_value=Mock(returncode=0, stdout="help"))
    monkeypatch.setattr(subprocess, "run", run)
    assert AircrackWrapper().aircrack_help() == "help"
    args, kwargs = run.call_args
    assert args[0] == ["/usr/bin/aircrack-ng", "--help"]
    assert not kwargs.get("shell") and kwargs["timeout"] == 8
    run.side_effect = subprocess.TimeoutExpired("test", 1)
    with pytest.raises(ToolError, match="time limit"):
        AircrackWrapper().list_airmon()
    run.side_effect = None
    run.return_value = Mock(returncode=1)
    with pytest.raises(ToolError, match="exit 1"):
        AircrackWrapper().list_airmon()
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolError, match="not installed"):
        AircrackWrapper().list_airmon()


@pytest.mark.parametrize(
    "value", ["wlan0;id", "../wlan0", "-bad", "wlan0 && whoami", "x" * 16, None]
)
def test_interface_injection(value):
    with pytest.raises(ValueError):
        interface_name(value)


def test_passive_command_is_scoped_csv_only(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    (tmp_path / "observation-01.csv").write_text("BSSID", encoding="utf-8")
    process = Mock()
    process.wait.side_effect = [subprocess.TimeoutExpired("scan", 5), 0]
    popen = Mock(return_value=process)
    monkeypatch.setattr(subprocess, "Popen", popen)
    result = AircrackWrapper().passive_scan("wlan0mon", "02:00:00:00:00:02", 6, 5, tmp_path)
    args = popen.call_args.args[0]
    assert args[1:5] == ["--bssid", "02:00:00:00:00:02", "--channel", "6"]
    assert args[args.index("--output-format") + 1] == "csv"
    assert "--deauth" not in args
    assert not popen.call_args.kwargs.get("shell")
    assert result.is_file()
    process.terminate.assert_called_once()


def test_csv_scope_and_station_sections(tmp_path):
    content = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, beacons, IV, IP, ID-length, ESSID, Key
02:00:00:00:00:02, 2026-09-24 10:00:00, 2026-09-24 10:00:02, 6, 54, WPA2, CCMP, PSK, -42, 4, 0, 0, 8, LAB-WPA2,
02:00:00:00:00:05, 2026-09-24 10:00:00, 2026-09-24 10:00:02, 6, 54, OPN, , , -52, 4, 0, 0, 8, EXCLUDED,
invalid, invalid, invalid, nope

Station MAC, First time seen, Last time seen, Power, packets, BSSID, Probed ESSIDs
02:00:00:01:00:02, 2026-09-24 10:00:00, 2026-09-24 10:00:02, -42, 4, 02:00:00:00:00:02, PRIVATE-PROBE
"""
    path = tmp_path / "scan.csv"
    path.write_text(content)
    result = parse_csv(path, ["02:00:00:00:00:02"])
    assert len(result) == 1
    assert result[0]["stations"] == ["02:00:00:01:00:02"]
    assert "PRIVATE-PROBE" not in str(result)


@pytest.mark.parametrize(
    "encryption,cipher,severity",
    [
        ("OPN", "", "High"),
        ("WEP", "WEP", "Critical"),
        ("WPA", "TKIP", "High"),
        ("WPA2", "CCMP", "Informational"),
        ("WPA3", "CCMP", "Informational"),
        ("UNKNOWN", "", "Low"),
    ],
)
def test_risk_engine(encryption, cipher, severity):
    findings = assess(dict(encryption=encryption, cipher=cipher, authentication="PSK"))
    assert findings[0]["severity"] == severity
    assert all(
        set(f) == {"title", "severity", "description", "evidence", "impact", "recommendation"}
        for f in findings
    )
    if encryption == "WPA2":
        assert "not automatically vulnerable" in findings[0]["description"]


def test_transition_mode_rules():
    findings = assess(dict(encryption="WPA WPA2", cipher="TKIP CCMP"))
    assert {f["severity"] for f in findings} == {"High", "Medium", "Informational"}
    assert assess(dict(encryption="OPN"), {"open": "Medium"})[0]["severity"] == "Medium"
