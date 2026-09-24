"""Read Linux sysfs and iw without changing device state."""

import re
from pathlib import Path

from scanners.aircrack_wrapper import AircrackWrapper, ToolError


def detect_interfaces():
    root = Path("/sys/class/net")
    if not root.is_dir():
        return []
    wrapper = AircrackWrapper()
    devices = []
    for path in sorted(root.iterdir()):
        if not (path / "wireless").exists() and not (path / "phy80211").exists():
            continue

        def read(name, path=path):
            try:
                return (path / name).read_text().strip()[:100]
            except OSError:
                return "unknown"

        mode, capable = "unknown", None
        try:
            info = wrapper._run("iw", ["dev", path.name, "info"])
            match = re.search(r"type\s+(\S+)", info)
            mode = match.group(1) if match else "unknown"
            phy = (path / "phy80211").resolve().name
            if re.fullmatch(r"phy[0-9]+", phy):
                phy_info = wrapper._run("iw", ["phy", phy, "info"])
                modes = re.search(
                    r"Supported interface modes:(.*?)(?:Band |valid interface|$)", phy_info, re.S
                )
                capable = bool(re.search(r"\*\s+monitor\b", modes.group(1))) if modes else None
        except (ToolError, OSError):
            pass
        driver_path = path / "device/driver"
        devices.append(
            dict(
                name=path.name,
                mac=read("address"),
                driver=driver_path.resolve().name if driver_path.exists() else "unknown",
                mode=mode,
                status=read("operstate"),
                monitor_capable=capable,
            )
        )
    return devices
