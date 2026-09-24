# Authorized laboratory setup

Use a router you own, dedicated Kali system/VM and monitor-capable USB adapter. Keep ordinary connectivity on Ethernet or another adapter. Record BSSID/channel from the router console and keep written permission identifying devices, operators and allowed times. Use synthetic mode for obsolete/open demonstrations instead of weakening real networks.

## Prepare monitor mode locally

```bash
iw dev
sudo airmon-ng start wlan0
iw dev
```

Substitute your dedicated interface name. The monitor name may become `wlan0mon`; use the actual detected name. The web application does not change mode. Do not use `airmon-ng check kill` here because it can disrupt unrelated network services. A VM typically needs USB passthrough. Driver/firmware/regulatory support limits usable channels even when a channel passes numeric validation.

## Unprivileged web server, approved radio permissions

Airodump needs packet-socket/radio privileges. On a dedicated lab machine an administrator may provision the trusted installed binary:

```bash
sudo apt install -y libcap2-bin
command -v airodump-ng
sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/airodump-ng
getcap /usr/sbin/airodump-ng
```

Use the actual absolute path from your installation. Do not grant capabilities to writable binaries or Python. This grants radio operations to users allowed to execute that binary; restrict access on shared machines and follow local lab policy. If capabilities are prohibited, use demo mode or ask the lab administrator to provide an approved execution environment. Never run the web server as root; no sudo password is accepted by the app.

## Assessment

1. Set `ENABLE_LIVE_SCAN=true` and restart the unprivileged local server.
2. Approve the BSSID, channel and existing permission reference in Settings.
3. Verify monitor interface/tool availability on Wireless interfaces.
4. Select Live discovery, the approved network and interface, and 5–60 seconds.
5. Confirm permission and submit. No clients are disconnected and no packet payload file is written.
6. Review factual observations and evidence-based recommendations; generate a PDF.
7. Independently verify remediation in the router's configuration.

An empty scan only means no usable matching observation was recorded during the interval. Airodump receives on a shared medium even with a filter; application post-filtering additionally excludes nonmatching AP records. An isolated lab minimizes incidental reception.

## Cleanup

Disable live scanning/revoke scope, stop monitoring and remove capabilities when no longer needed:

```bash
sudo airmon-ng stop wlan0mon
sudo setcap -r /usr/sbin/airodump-ng
```

Use actual device/binary paths and respect other users' connectivity. Hardware acceptance should record Kali/Aircrack versions, adapter, driver, channel, scoped output and cleanup. Windows development verified mocked command lifecycle/parser behavior, not actual radio operation.
