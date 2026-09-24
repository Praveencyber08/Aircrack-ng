# Troubleshooting

| Symptom | Resolution |
|---|---|
| Missing tables | Initialize DB using the same environment/config as the server. |
| Cannot sign in | Use CLI-created credentials; prepared demo details are in instance/first-login.txt. There is no shared default password. |
| CSRF expired/missing | Reload form; API needs a fresh token after login and the session cookie. |
| Session disappears on HTTP | Keep COOKIE_SECURE=false for local HTTP; use true only with HTTPS. |
| No interfaces | Live needs Linux sysfs/iw and an exposed wireless adapter; demo remains available. |
| Monitor capability unknown | Driver/iw did not advertise enough information; inspect locally. |
| Live option missing | Enable it in .env and restart; approve scope in Settings. |
| Missing tool | Install Aircrack-ng/iw and check service-user PATH. |
| Scan fails/no CSV | Check monitor mode, capabilities, binary and adapter support. Do not run the web server as root. |
| Zero networks | Check BSSID/channel/range/duration; unusable rows are skipped. |
| Upload rejected | Check file framing, 802.11 link type, scope, size and packet count. |
| EAPOL zero | No matching EAPOL detected; no claim about authentication security follows. |
| Channel unknown | DS parameter elements absent; HT/VHT/HE channel decoding is not implemented. |
| Missing PDF | Check private REPORT_DIR and permissions; restoring a DB row alone does not restore a PDF. |
| Unicode `?` in PDF | Built-in fonts use Latin-1; web UI retains Unicode. |
| 429 | Wait for the rate-limit interval. |
| Port occupied | Stop old server or choose --listen=127.0.0.1:5001. |
| No libpcap provider on Windows | Offline Scapy parsing still works; live sniffing is not performed through Scapy. |
| Stale running scan after crash | Preserve as interrupted evidence, inspect private temp files and rerun; no durable job recovery exists. |

Do not include secrets, first-login files or raw captures in bug reports. Use safe errors, versions and synthetic examples. Unexpected exceptions are hidden from normal users. Back up before schema changes; initialization does not migrate an old schema.
