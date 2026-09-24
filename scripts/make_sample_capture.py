"""Generate synthetic beacon and EAPOL metadata for the college demonstration."""

from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP
from scapy.utils import wrpcap


def main():
    root = Path(__file__).resolve().parents[1] / "instance" / "samples"
    root.mkdir(parents=True, exist_ok=True)
    bssid = "02:00:00:00:00:02"
    beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID="SSID", info=b"LAB-WPA2")
        / Dot11Elt(ID="DSset", info=b"\x06")
    )
    frame = (
        RadioTap()
        / Dot11(type=2, subtype=0, FCfield=1, addr1=bssid, addr2="02:00:00:01:00:02", addr3=bssid)
        / LLC(dsap=170, ssap=170, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=2, type=0)
    )
    path = root / "DEMO-LAB-WPA2.pcap"
    wrpcap(str(path), [beacon] * 6 + [frame])
    print(f"Synthetic metadata sample (no credentials): {path}")


if __name__ == "__main__":
    main()
