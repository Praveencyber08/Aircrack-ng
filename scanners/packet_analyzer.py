"""Bounded offline metadata extraction. Never serializes packet payloads."""

import json
import struct
import sys
from collections import Counter
from pathlib import Path

MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


def validate_container(path):
    # Validate framing first: Scapy may treat truncated files as EOF.
    with open(path, "rb") as stream:
        magic = stream.read(4)
        stream.seek(0)
        size = Path(path).stat().st_size
        if magic not in MAGICS:
            raise ValueError("File is not a supported packet capture.")
        if magic != b"\x0a\x0d\x0d\x0a":
            endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            if len(stream.read(24)) != 24:
                raise ValueError("Truncated capture header.")
            while stream.tell() < size:
                header = stream.read(16)
                if len(header) != 16:
                    raise ValueError("Truncated packet header.")
                _, _, length, original = struct.unpack(endian + "IIII", header)
                if length > original or length > size - stream.tell():
                    raise ValueError("Invalid packet length.")
                stream.seek(length, 1)
        else:
            endian = None
            while stream.tell() < size:
                start = stream.tell()
                header = stream.read(12)
                if len(header) != 12:
                    raise ValueError("Truncated pcapng block.")
                if header[:4] == b"\x0a\x0d\x0d\x0a":
                    if header[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                        raise ValueError("Invalid pcapng byte order.")
                    endian = "<" if header[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
                if endian is None:
                    raise ValueError("Missing pcapng section.")
                length = struct.unpack(endian + "I", header[4:8])[0]
                if length < 12 or length % 4 or start + length > size:
                    raise ValueError("Invalid pcapng block length.")
                stream.seek(start + length - 4)
                if struct.unpack(endian + "I", stream.read(4))[0] != length:
                    raise ValueError("Invalid pcapng block trailer.")


def analyze(path, allowed_bssid, packet_limit=100000):
    from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11Beacon, Dot11Elt, Dot11ProbeResp
    from scapy.layers.eap import EAPOL
    from scapy.utils import PcapReader

    validate_container(path)
    protocols, channels = Counter(), set()
    total = matched = eapol = authentication = 0
    with PcapReader(str(path)) as reader:
        for packet in reader:
            total += 1
            if total > packet_limit:
                raise ValueError("Capture exceeds the packet analysis limit.")
            if not packet.haslayer(Dot11):
                continue
            dot = packet[Dot11]
            ds = int(dot.FCfield) & 3
            bssid = (
                dot.addr3 if ds == 0 else dot.addr1 if ds == 1 else dot.addr2 if ds == 2 else None
            )
            if not bssid or bssid.upper() != allowed_bssid.upper():
                continue
            matched += 1
            protocols["802.11"] += 1
            if packet.haslayer(EAPOL):
                eapol += 1
                protocols["EAPOL"] += 1
            if packet.haslayer(Dot11Auth):
                authentication += 1
                protocols["802.11 authentication"] += 1
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                protocols["Beacon / probe response"] += 1
                element = packet.getlayer(Dot11Elt)
                for _ in range(256):
                    if not isinstance(element, Dot11Elt):
                        break
                    if element.ID == 3 and len(element.info) == 1:
                        channels.add(element.info[0])
                    element = element.payload
    if not matched:
        raise ValueError("No 802.11 packets matched the selected authorized BSSID.")
    return dict(
        packet_count=total,
        scoped_packet_count=matched,
        excluded_packet_count=total - matched,
        protocols=dict(protocols),
        bssids=[allowed_bssid.upper()],
        channels=sorted(channels),
        eapol_frames=eapol,
        authentication_frames=authentication,
        handshake_note="EAPOL counts do not establish a complete 4-way handshake or a vulnerability.",
        retention="Raw upload deleted after processing. No payloads or credentials retained.",
    )


if __name__ == "__main__":
    try:
        # Linux resource limits supplement the parent's wall-clock timeout.
        if sys.platform == "linux":
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        result = analyze(sys.argv[1], sys.argv[2], int(sys.argv[3]))
        print(json.dumps(result))
    except Exception:
        print(json.dumps({"error": "Invalid, unsupported, out-of-scope or over-limit capture."}))
        sys.exit(2)
