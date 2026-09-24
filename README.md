# Spectra: Wi-Fi Security Assessment and Vulnerability Analysis Using Aircrack-ng

A working, free/open-source college project for authorized wireless configuration assessment. Flask, SQLAlchemy and SQLite power the application; Bootstrap 5 and Chart.js provide the responsive interface; ReportLab creates PDFs. Kali Linux and Aircrack-ng support passive live discovery. Demo mode works on Windows/Linux without a wireless adapter.

## Quick start: Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip aircrack-ng iw
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app app:create_app init-db
flask --app app:create_app create-admin
waitress-serve --listen=127.0.0.1:5000 --threads=4 --call app:create_app
```

Open http://127.0.0.1:5000 and sign in with the administrator you created. The hidden password prompt requires 12–128 characters. No default shared password is shipped. An empty SECRET_KEY causes a random persistent local secret to be created in `instance/.secret_key`.

## This prepared workspace

The local demo has a random `demo-admin` password in the ignored `instance/first-login.txt`. Change it using the account link after first sign-in, then delete that file. The server was launched at http://127.0.0.1:5000 during verification. Restart from PowerShell:

```powershell
.\.venv\Scripts\python -m waitress --listen=127.0.0.1:5000 --threads=4 --call app:create_app
```

For a fresh Windows installation use `python -m venv .venv`, `.\.venv\Scripts\python -m pip install -r requirements.txt`, then equivalent `python -m flask` initialization commands. Live radio discovery requires Linux.

## Demo mode and college demonstration

1. Leave `DEMO_MODE=true` and `ENABLE_LIVE_SCAN=false`.
2. Sign in; open Network discovery; choose Demo laboratory.
3. Confirm authorization for synthetic lab data and start discovery.
4. Show LAB-WIFI (WEP), LAB-WPA2 (CCMP/PSK), LAB-WPA3 (CCMP/SAE), LAB-OPEN.
5. Show four dashboard networks, two requiring review; Critical 1, High 1, Informational 2 under default rules.
6. Inspect LAB-WIFI's evidence and recommendation; explain why WPA2 is informational rather than automatically vulnerable.
7. Select 2–4 inventory networks and compare their observed attributes.
8. Run `python scripts/make_sample_capture.py`; upload `instance/samples/DEMO-LAB-WPA2.pcap` for LAB-WPA2 with authorization.
9. Show seven packets, channel 6 and one synthetic EAPOL frame. This is not a real handshake or credential.
10. Generate/download a PDF, then show the administrator audit trail.
11. Create an analyst account to demonstrate restricted access to Users, Settings and Audit logs.

Synthetic data is labeled **DEMO DATA — NOT LIVE NETWORK DATA**. Repeated scans update four inventory records and append observation/assessment history. Failed live scans never substitute demo results.

## Authorized live assessment

Read [lab setup](docs/lab-setup.md). Approve an owned BSSID, channel and permission reference in Settings. Configure monitor mode outside the application on a dedicated Kali adapter. Enable `ENABLE_LIVE_SCAN=true`, restart, select the approved BSSID and detected monitor interface, and confirm authorization. Airodump-ng produces CSV only for 5–60 seconds; only matching BSSIDs are persisted. The web application does not change interface mode or use sudo.

## Implemented capabilities

- Scrypt password hashes, Admin/Analyst roles, expiring sessions, password rotation, session revocation and soft user deletion.
- Dashboard charts/statistics, scan/report history, responsive navigation, loading states, confirmation modals and notifications.
- Linux sysfs/iw interface, driver/status/mode/capability detection and missing-hardware states.
- Scoped airodump-ng discovery, safe argument arrays, timeouts, CSV parsing, stations and history.
- Configurable evidence-only rules for open, WEP, WPA, TKIP, WPA2, WPA3 and unknown configurations.
- Temporary capture uploads, framing validation, bounded subprocess analysis, scoped protocol/BSSID/channel/EAPOL metadata and raw-file deletion.
- Search, encryption/severity/channel/date/source filters, pagination and network comparison.
- Immutable PDF assessment snapshots, authenticated downloads, audit logs and CSRF-protected REST APIs.

## Project layout

```text
app.py / config.py           Startup and environment settings
app/__init__.py             Factory and database/admin CLI
app/models/                 SQLAlchemy schema
app/security/               Authorization, validation, audit helpers
app/routes/                 Authentication, HTML and REST
app/services/               Workflows, queries and risk engine
app/templates/              Jinja pages
app/static/                 CSS, JS and vendored MIT libraries
scanners/                   Aircrack wrapper, interfaces, CSV, captures
reports/                    ReportLab renderer
scripts/                    Demo setup and synthetic capture generator
tests/                      Functional/security tests
docs/                       Technical and academic documentation
database/                   Schema/retention notes
screenshots/                Verified UI screenshots
instance/                   Ignored DB, secret, reports, uploads
output/pdf/                 Generated sample PDF
```

## Verification

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check app scanners reports scripts tests config.py app.py
ruff format --check app scanners reports scripts tests config.py app.py
```

See [testing](docs/testing.md) for actual results and hardware limits. Verified dependencies are recorded in `requirements-lock.txt` and `requirements-dev-lock.txt`. The normal requirements permit compatible updates.

## Limitations

This is a small, shared-trust lab application, not a multi-tenant hosted service. Analysts can view all lab networks/reports. Audit history is not tamper-proof against a database administrator. SQLite and synchronous bounded scans suit a small lab; serialize live scans on one adapter. A crash may leave running scan records or temporary files.

No cracking, deauthentication, injection, credential extraction/display or Wi-Fi password storage is implemented. `aircrack-ng` supports fixed help diagnostics; `airmon-ng` supports read-only listing; `airodump-ng` performs passive scoped CSV collection. `aireplay-ng` is unnecessary and is not invoked. Capture metadata does not validate handshake completeness or exploitability. Non-802.11/nonmatching captures are rejected; channel extraction currently uses DS parameter elements.

See [security](docs/security.md), [architecture](docs/architecture.md), [project report](docs/project-report.md), [15-slide content](docs/presentation.md) and [50 viva questions](docs/viva.md). App code is MIT licensed; dependencies retain their own licenses.
