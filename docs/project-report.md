# Wi-Fi Security Assessment and Vulnerability Analysis Using Aircrack-ng

## Abstract

Wireless networks are convenient but difficult to assess consistently when observations, permission records and recommendations are scattered across terminal output and manual notes. This project implements Spectra, a web-based platform that converts authorized wireless observations into traceable security assessments. It combines Kali Linux and Aircrack-ng for passive discovery with Python, Flask, SQLAlchemy and SQLite for application logic and persistence. A Bootstrap and Chart.js interface presents network inventories and severity statistics, while ReportLab generates portable reports. An isolated offline analyzer extracts scoped capture metadata without retaining credentials or packet payloads. Synthetic demonstration data makes the complete workflow reproducible without a compatible adapter. The project evaluates observed configurations rather than asserting that an advertised protocol proves exploitability. Automated tests validate the application and mocked scanner boundaries; actual radio performance remains a separate Kali hardware acceptance step.

## 1. Introduction

Wi-Fi extends a local network over a shared radio medium. Security therefore depends on appropriate encryption, authentication, device configuration and maintenance. An assessment should explain what was observed, why it matters and what evidence is still missing. It should also document permission before collecting data. This project organizes that process in a single local laboratory workspace suitable for teaching defensive assessment.

The title includes vulnerability analysis because obsolete configurations can indicate meaningful weaknesses. The application does not exploit those weaknesses or prove compromise. It records evidence and potential impact, helping an analyst prioritize defensive review.

## 2. Problem statement

Students using wireless command-line tools often have no structured way to retain authorization, normalize results, compare configurations, avoid unsupported security claims, or generate repeatable reports. Hardware availability can also prevent a classroom demonstration. A complete solution must combine practical tool integration with safe boundaries, reproducible demonstration data and clear reporting.

## 3. Existing system

A manual workflow typically involves configuring an adapter, running a terminal scanner, reading CSV or capture files, assigning severity by hand and writing a report. This approach offers flexibility but makes transcription errors, inconsistent interpretation and missing audit evidence more likely. Raw captures can also contain unnecessary sensitive material. Terminal tools remain valuable; the proposed platform gives their authorized outputs a structured application workflow.

## 4. Proposed system

Spectra provides authenticated administrator and analyst access, approved live BSSID scopes, passive discovery, network history, metadata-only capture analysis, configurable rules and immutable PDF snapshots. Demo mode supplies four clearly synthetic networks. HTML forms and REST APIs share the same services, keeping scope and validation consistent. No password recovery or disruptive operation is provided.

## 5. Objectives

- Collect only authorized wireless observations and record operator confirmation.
- Present factual encryption, cipher, authentication, signal, channel and station data.
- Identify obsolete/unknown configurations using documented, configurable rules.
- Separate observations from potential impacts and unverified assumptions.
- Minimize capture retention and protect application inputs, sessions and files.
- Produce consistent, readable assessment reports and audit records.
- Support a complete classroom demonstration without special hardware.

## 6. Scope

The reference deployment is one small shared-trust lab server bound to loopback. Administrators define scopes and users; analysts assess approved networks. Supported capture formats are cap, pcap and pcapng containing matching 802.11 frames. The application does not determine passphrase strength, verify a full handshake, test firmware exploits, recover credentials or audit router administration interfaces. It is not an internet-scale scanner, multi-tenant platform or compliance certification system.

## 7. Technology overview

| Technology | Role |
|---|---|
| Kali Linux | Optional live wireless lab operating system |
| Aircrack-ng suite | Scoped passive airodump collection and tool diagnostics |
| Python 3 / Flask | Modular application and HTTP routing |
| SQLAlchemy / SQLite | Relational persistence, queries and constraints |
| HTML5 / CSS3 / JavaScript | Semantic responsive interface and interaction |
| Bootstrap 5 | Forms, modal confirmations and notifications |
| Chart.js | Severity and channel visualizations |
| Scapy | Offline 802.11 metadata decoding |
| ReportLab | Paginated PDF generation |
| pytest / Ruff | Automated verification and code formatting/linting |
| Waitress | Local WSGI service |

These components are free/open-source, with their individual licenses preserved. Frontend assets are vendored to support offline presentation after installation.

## 8. System requirements

Python 3.11 or later, a modern browser and a writable private data directory are required. A modest laptop can run the demo. Capture requests are capped at 16 MiB and 100,000 packets; Linux parser processes are capped at 512 MiB address space and 20 seconds CPU, with a 30-second parent deadline. Live discovery additionally requires Linux, iw, Aircrack-ng and a compatible adapter already configured in monitor mode. VM users generally need USB passthrough.

## 9. Architecture

The browser sends authenticated HTML/API requests to Flask. Session validation, CSRF, role checks and input validation run before workflow services. Discovery services select a synthetic provider or the constrained airodump wrapper. Capture services invoke a bounded child process. Rules turn observed facts into findings. SQLAlchemy stores records and ReportLab renders snapshots. This separation allows deterministic rule/parser testing independent of hardware.

See architecture.md for a Mermaid diagram and full lifecycle. Live operations are synchronous with 5–60 second observation windows; a durable background queue is future work.

## 10. Modules

Authentication includes secure hashing, logout, password changes and session invalidation. Dashboard aggregates inventory and current findings. Interface detection reads Linux sysfs/iw without changing device state. Discovery parses scoped CSV and keeps AP/station metadata. Inventory supports detail/history, filters and comparison. Capture analysis validates structure and extracts scoped counts. Assessment rules produce title, severity, description, evidence, potential impact and recommendation. Reports preserve the selected assessment. Administration handles scope, rule settings, users and audit access.

## 11. Database design

The required tables are users, wireless_interfaces, networks, scans, findings, captures, reports and audit_logs. Additional scopes, observations, assessments and settings support authorization and historical integrity. A user can create many scans and assessments. A network has many observations and assessments; each assessment owns its findings. A report references one assessment, ensuring later changes do not rewrite the report's evidence.

Networks are unique by BSSID and demo flag. SQLite foreign keys are enabled on every connection. Indexed columns cover BSSIDs, references, timestamps, severity and audit lookups. Soft deletion preserves user attribution while revoking access. JSON columns hold bounded configuration/evidence snapshots and metadata; raw packet bodies are excluded.

## 12. Implementation

### Discovery

The server validates confirmation, mode, approved BSSID, duration and detected monitor interface. It records a running scan, invokes a fixed airodump argument array with BSSID/channel/CSV settings, bounds execution, terminates/reaps the child and parses output. AP and station sections are handled separately. Nonmatching APs and station probe lists are discarded. Successful observations and findings are committed together; expected failures produce failed scan records.

### Demo provider

Synthetic networks use locally administered MAC addresses and fixed lab names. LAB-WIFI advertises WEP, LAB-OPEN is open, LAB-WPA2 uses CCMP/PSK and LAB-WPA3 uses CCMP/SAE. Repeated scans update current facts and add historical observations. Demo labeling is visible in inventory, detail, reports and the dashboard. Synthetic capture generation creates beacon/EAPOL metadata without credentials.

### Assessment algorithm

For each fact snapshot, normalize encryption/cipher strings. Apply open, WEP, legacy WPA, TKIP and unknown rules; add informational WPA2/WPA3 observations when present. Multiple rules may apply to a mixed configuration. Save the effective rule configuration and finding evidence with the assessment. Mark older findings noncurrent without deleting them. The highest finding severity is used as a report summary, not a mathematical exploitability score.

### Capture analysis

Reject unsafe names, unsupported extensions and oversized requests. Save temporarily using a generated filename. Check pcap/pcapng signatures and block/packet framing before streaming Scapy decoding. Determine BSSID from 802.11 address/DS flags, count only scoped protocol metadata and retain detected DS channel elements. Delete the raw file after processing. EAPOL count explicitly does not prove complete handshake capture.

### Reporting

ReportLab builds a cover, executive summary, scope/authorization, network configuration table, evidence limitations, findings, impacts, recommendations, conclusion and metadata. User-provided text is XML-escaped. Repeated table headers, controlled margins and footers support pagination. Reports require authentication and use generated private paths.

## 13. Security mechanisms

Application passwords use Werkzeug scrypt hashes. Sessions use a random signing key, HttpOnly/SameSite cookies, a 30-minute lifetime and per-user session version. All mutations require CSRF. Administrator-only views enforce roles server-side. Queries use bound parameters, rendered values are escaped and subprocesses use arrays without a shell. Uploads are bounded and temporary; filenames cannot select paths. Rate limits constrain repeated expensive operations. Production debug is disabled and unexpected failures return safe messages.

These controls have limits. A local database administrator can modify records; audit logs are not cryptographically tamper-evident. A parser child uses the service identity, not a full container sandbox. All authenticated lab members share the inventory. Temporary files may remain after process termination. Security documentation describes these operational responsibilities.

## 14. Testing methodology

Pytest uses a fresh in-memory database and private temporary directories per test. Functional tests cover login/logout, roles, demo discovery, all HTML pages, APIs, filters, history, settings, password rotation and report downloads. Security tests cover CSRF, SQL-like inputs, XSS escaping, missing scope, file traversal/extensions/size, malformed/truncated captures and subprocess validation. Scanner tests mock binaries and process lifecycles; offline fixtures exercise all three supported capture formats. PDF tests parse generated documents, and rendered pages are visually inspected.

The exact latest counts and commands are in testing.md. Browser acceptance exercised actual login, synthetic discovery, network details and report creation on the local Waitress service. Screenshots document desktop/mobile checks. Hardware behavior is explicitly excluded from these measured results.

## 15. Results

The tested default demo produced four inventory networks, four current findings and two networks requiring review. WEP was Critical, open wireless High, WPA2/CCMP and WPA3/CCMP Informational. Repeated discovery preserved inventory uniqueness while adding history. The synthetic LAB-WPA2 capture generated seven packets with one EAPOL frame and channel 6 metadata. Reports preserved their bytes after underlying network edits in automated tests. Unauthorized administrator views and out-of-scope mutations were rejected. Generated PDF pages were readable without clipped content.

These results demonstrate application behavior and safe metadata handling; they do not establish any real network vulnerability, live adapter compatibility or security certification.

## 16. Advantages

The project combines practical defensive assessment, historical evidence and reporting in one interface. A shared service layer keeps API/UI validation aligned. Demo mode removes hardware dependence for classroom use. Data minimization avoids long-term raw capture storage. Configurable classifications and explicit evidence limitations support defensible explanations rather than automatic claims of compromise.

## 17. Limitations

Actual Kali radio acquisition remains unverified here. The synchronous scanner is intended for serial operation on a small lab adapter. WPA3 recognition depends on tool output and is not independent protocol verification. Capture channel extraction does not cover every modern information element. Ethernet-only captures are unsupported. PDF built-in fonts replace unsupported Unicode with question marks. There is no MFA, distributed job queue, signed audit chain, tenant isolation, automatic retention or database migration framework.

## 18. Future scope

Add a privilege-separated scanner worker with per-adapter locks; durable jobs/cancellation; richer RSN/PMF/HT/VHT/HE decoding; explicit scope expiry and per-user assignment; signed or external audit storage; embedded Unicode fonts; optional MFA; managed retention and database migrations. Any enhancement should preserve authorization, evidence quality and exclusion of credential recovery or disruptive operations.

## 19. Conclusion

Spectra implements a complete local workflow from permission confirmation and observation through evidence-based assessment and PDF reporting. It provides a reproducible teaching environment and a constrained integration path for an authorized Kali wireless laboratory. Its main contribution is traceable, understandable defensive analysis, with explicit separation between tested application behavior and hardware-dependent or unverified security claims.

## 20. References

1. [Aircrack-ng: airodump-ng documentation](https://www.aircrack-ng.org/doku.php?id=airodump-ng)
2. [Scapy: 802.11 layer reference](https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html)
3. [Flask: security considerations](https://flask.palletsprojects.com/en/stable/web-security/)
4. [SQLAlchemy documentation](https://docs.sqlalchemy.org/)
5. [ReportLab documentation](https://docs.reportlab.com/)
6. [NIST: WPA2 glossary](https://csrc.nist.gov/glossary/term/wi_fi_protected_access_2)
7. [Bootstrap documentation](https://getbootstrap.com/docs/5.3/)
8. [Chart.js documentation](https://www.chartjs.org/docs/latest/)

Submission note: add your actual institution, department, student names/IDs, supervisor and academic year to the cover required by your college. No personal academic details or hardware test results have been invented.
