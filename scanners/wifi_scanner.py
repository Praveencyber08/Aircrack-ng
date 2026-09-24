"""Parse airodump CSV with explicit AP/station sections and scope filtering."""

import csv
from datetime import datetime

from app.security import mac


def parse_csv(path, allowed_bssids):
    allowed = {mac(value) for value in allowed_bssids}
    networks, section = {}, None
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        for index, raw in enumerate(csv.reader(handle)):
            if index > 50000:
                raise ValueError("Scan CSV exceeds row limit.")
            row = [cell.strip() for cell in raw]
            if not row:
                continue
            if row[0] == "BSSID":
                section = "ap"
                continue
            if row[0] == "Station MAC":
                section = "station"
                continue
            try:
                if section == "ap" and len(row) >= 14:
                    bssid = mac(row[0])
                    if bssid not in allowed:
                        continue
                    channel, signal = int(row[3]), int(row[8])
                    if not 1 <= channel <= 233 or not -127 <= signal <= 0:
                        continue
                    first = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S").isoformat()
                    last = datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S").isoformat()
                    networks[bssid] = dict(
                        bssid=bssid,
                        essid=row[13][:128] or "<hidden>",
                        channel=channel,
                        encryption=row[5][:64],
                        cipher=row[6][:64],
                        authentication=row[7][:64],
                        signal=signal if signal != -1 else None,
                        first_seen=first,
                        last_seen=last,
                        stations=[],
                    )
                elif section == "station" and len(row) >= 6:
                    bssid = row[5].upper()
                    if bssid in networks and len(networks[bssid]["stations"]) < 500:
                        station = mac(row[0])
                        if station not in networks[bssid]["stations"]:
                            networks[bssid]["stations"].append(station)
            except (ValueError, IndexError):
                continue
    return list(networks.values())
