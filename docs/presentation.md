# Presentation content — 15 slides

This is ready-to-copy PPT content with speaker notes, not a generated .pptx file. Use the saved dashboard screenshots and the sample assessment PDF during the demonstration.

## Slide 1 — Title

**Wi-Fi Security Assessment and Vulnerability Analysis Using Aircrack-ng**
Spectra: an authorized defensive laboratory platform.
Add your actual student, department and supervisor details.

Speaker note: Explain that the project assesses evidence and does not recover passwords or disrupt networks.

## Slide 2 — Introduction

- Wi-Fi extends connectivity over a shared radio medium.
- Configuration affects confidentiality and access protection.
- Observations need clear interpretation and documentation.

Speaker note: Distinguish observed configuration from verified exploitability.

## Slide 3 — Problem statement

- Terminal results and manual notes are fragmented.
- Permission and evidence are often poorly recorded.
- Hardware availability can block classroom demonstrations.

Speaker note: Show why a reusable workflow matters beyond running a command.

## Slide 4 — Objectives

- Scope and record authorized assessments.
- Discover networks and inspect capture metadata.
- Generate evidence-based findings and recommendations.
- Produce auditable PDF reports.

Speaker note: Emphasize correctness and traceability over attack capability.

## Slide 5 — Existing system

- Manual tool execution and CSV interpretation.
- Repeated report-writing and inconsistent severity labels.
- Risk of retaining unnecessary packet data.

Speaker note: Terminal tools remain useful; the app organizes their safe outputs.

## Slide 6 — Proposed system

- Authenticated web workspace with two roles.
- Approved live BSSID scopes and explicit confirmation.
- Shared services for UI and API.
- Complete synthetic demo mode.

Speaker note: Show the login page and explain administrator versus analyst.

## Slide 7 — Architecture

Browser → Flask security/routes → workflow services → scanner/capture/rules → SQLAlchemy/SQLite → ReportLab.

Visual: use the Mermaid architecture diagram in architecture.md.
Speaker note: Capture decoding runs in a bounded child process; hardware is optional for demo.

## Slide 8 — Technologies

- Kali Linux, Aircrack-ng, Python 3, Flask.
- SQLAlchemy, SQLite, Scapy.
- HTML/CSS/JavaScript, Bootstrap 5, Chart.js.
- ReportLab, pytest, Ruff, Waitress.

Speaker note: All components are free/open-source; local frontend assets allow offline presentation.

## Slide 9 — Aircrack-ng components

- airodump-ng: scoped passive CSV observations.
- airmon-ng: read-only diagnostic listing; monitor setup is local.
- aircrack-ng: fixed help diagnostics only.
- No cracking, deauthentication or aireplay execution.

Speaker note: Explain argument arrays, validation and bounded process lifetime.

## Slide 10 — Application modules

Authentication; dashboard; interfaces; discovery; inventory/history; capture analysis; rule engine; reports; audit; users/settings; REST API.

Speaker note: Trace one network through the lifecycle rather than listing menu items only.

## Slide 11 — Dashboard demonstration

- Four demo networks and two requiring review.
- Severity distribution and observed channels.
- Recent scans/reports; visible demo labels.

Visual: screenshots/dashboard-desktop.png.
Speaker note: Repeat a scan and explain why history increases without duplicating inventory.

## Slide 12 — Security assessment

- WEP → Critical; open → High under default rules.
- WPA2/CCMP and WPA3 → Informational observations.
- Every finding has evidence, impact and recommendation.
- Severity is configurable and stored with each assessment.

Speaker note: WPA2 is not automatically vulnerable. Signal strength is not a security grade.

## Slide 13 — Results and verification

- Demo, authentication, APIs, capture metadata and PDFs verified.
- Automated tests cover positive and adversarial inputs.
- Browser workflows and rendered PDF layout checked.
- Actual Kali radio operation requires a compatible-adapter acceptance test.

Speaker note: Quote the latest test count from testing.md. Do not present mocked tests as hardware validation.

## Slide 14 — Future scope

- Privilege-separated scanner worker and durable jobs.
- More wireless information-element decoding.
- Scope expiry, MFA, stronger audit integrity.
- Unicode PDF fonts and managed retention.

Speaker note: Preserve permission checks and data minimization in every extension.

## Slide 15 — Conclusion

- A functioning, traceable defensive assessment workflow.
- Reproducible without special hardware.
- Clear evidence, practical recommendations and honest limitations.

Live close: show a PDF, the capture metadata page and the audit event. Invite questions using viva.md.
