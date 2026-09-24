# Verification record

Date: 24 September 2026. Environment: Windows, Python 3.14, local Waitress service and Chromium-based in-app browser. Exact Python packages are recorded in requirements-lock.txt and requirements-dev-lock.txt.

## Automated results

`python -m pytest -q`: **67 passed in 35.95 seconds**.

The suite uses isolated SQLite databases, private temporary directories, synthetic captures and mocked radio processes. No real network was scanned by the tests.

| Area | Verified behavior |
|---|---|
| Authentication | Login/logout, invalid credentials, scrypt hashing, password rotation and session revocation |
| Authorization | Admin-only pages/API, analyst assessment access, approved scope/revocation, disabled live/demo gates |
| Database | Foreign keys, unique usernames, demo network upserts, observation history and finding snapshots |
| UI/routes | Dashboard and all requested pages render, comparison accepts 2â€“4 networks |
| APIs | Authentication, pagination/filtering, mutation validation and report listings/downloads |
| Web security | CSRF enforcement, security headers, literal search escaping, stored XSS escaping, rate limiting |
| Uploads | Filename traversal, extensions, content framing, size, scope, timeout and cleanup |
| Captures | cap/pcap/pcapng fixtures, EAPOL/channel metadata, truncation and packet limits |
| Risk engine | Open, WEP, WPA, TKIP, WPA2, WPA3, unknown and configurable severities |
| PDF | Valid multi-page output, required content, immutable bytes and rollback on generation failure |
| Scanner | Fixed arrays, scope filtering, timeouts, nonzero/missing tools, termination/reaping, failure history |
| Demo | Four networks, stable inventory IDs, new history and four current default findings |

Ruff lint: **all checks passed**. Ruff format: **27 files already formatted**. `pip check`: **no broken requirements found**.

## Browser acceptance

Verified actual login, demo scan, inventory/detail view and PDF creation through the browser. Uploaded the generated synthetic LAB-WPA2 pcap: 522 bytes, seven scoped packets, six beacons, one EAPOL frame, channel 6. The UI confirmed raw-file deletion. Mobile 390x844 layout had no horizontal page overflow, and the menu toggle expanded/collapsed. Desktop layout was checked at 1440x1100. No browser console errors were observed. Screenshots are under screenshots/.

A first/last-seen ordering issue and a severity chart color mapping issue discovered during review were fixed. PDF output was rendered with Poppler and all three sample pages visually inspected for clipping, alignment and legibility. Poppler emitted missing fallback-font notices, but the actual Helvetica content rendered correctly.

## Reproduce

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
ruff check app scanners reports scripts tests config.py app.py
ruff format --check app scanners reports scripts tests config.py app.py
```

CSRF is disabled in most unit fixtures to isolate business behavior and explicitly enabled in a dedicated end-to-end test. Rate limits have a separate enabled test. This avoids claiming controls were tested merely because they were configured.

## Not verified here

No physical Kali adapter was available. Actual monitor capability, radio permissions, RF discovery, driver/channel compatibility and output variation across installed Aircrack builds require the hardware acceptance procedure in lab-setup.md. Mocked live workflow tests do not replace it. No performance benchmark, independent penetration test, regulatory compliance certification or internet-facing deployment validation is claimed.
