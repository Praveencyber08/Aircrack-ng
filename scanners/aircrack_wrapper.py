"""Narrow command surface: passive discovery and read-only tool diagnostics."""

import re
import shutil
import subprocess
from pathlib import Path


class ToolError(RuntimeError):
    pass


def interface_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", value):
        raise ValueError("Invalid wireless interface name.")
    return value


class AircrackWrapper:
    def _run(self, tool, args, timeout=8):
        executable = shutil.which(tool)
        if not executable:
            raise ToolError(f"{tool} is not installed or is not on PATH.")
        try:
            result = subprocess.run(
                [executable, *args],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{tool} exceeded its time limit.") from exc
        except OSError as exc:
            raise ToolError(f"Unable to start {tool}.") from exc
        if result.returncode != 0:
            raise ToolError(
                f"{tool} failed (exit {result.returncode}); check adapter permissions and configuration."
            )
        return result.stdout[:65536]

    def diagnostics(self):
        # No capture or dictionary arguments are accepted by this entry point.
        return {
            name: bool(shutil.which(name))
            for name in ("airmon-ng", "airodump-ng", "aircrack-ng", "iw")
        }

    def list_airmon(self):
        return self._run("airmon-ng", [])

    def aircrack_help(self):
        return self._run("aircrack-ng", ["--help"])

    def passive_scan(self, interface, bssid, channel, duration, directory):
        from app.security import integer, mac

        interface = interface_name(interface)
        bssid = mac(bssid)
        channel = integer(channel, "Channel", 1, 233)
        duration = integer(duration, "Duration", 5, 60)
        directory = Path(directory).resolve(strict=True)
        if not directory.is_dir():
            raise ValueError("Invalid scan directory.")
        executable = shutil.which("airodump-ng")
        if not executable:
            raise ToolError("airodump-ng is not installed.")
        prefix = directory / "observation"
        args = [
            executable,
            "--bssid",
            bssid,
            "--channel",
            str(channel),
            "--write",
            str(prefix),
            "--output-format",
            "csv",
            "--write-interval",
            "1",
            interface,
        ]
        try:
            # Direct output to files to avoid unbounded pipe buffers during scanning.
            with (directory / "stderr.txt").open("wb") as err:
                process = subprocess.Popen(
                    args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err
                )
                try:
                    code = process.wait(timeout=duration)
                    if code != 0:
                        raise ToolError(
                            f"airodump-ng failed (exit {code}); check monitor mode and permissions."
                        )
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
        except OSError as exc:
            raise ToolError("Unable to start passive discovery.") from exc
        output = directory / "observation-01.csv"
        if not output.is_file():
            raise ToolError("No CSV was produced; check adapter support and permissions.")
        return output
