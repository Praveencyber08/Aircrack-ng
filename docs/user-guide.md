# User guide

## Access and roles

Use the account created during installation. Administrators manage scope, rules, users and audit access. Analysts run assessments and view shared lab records. Click your account name to change the application password; this invalidates other sessions. User deletion revokes access while retaining historical identity. Sign out when finished.

## Overview and discovery

The dashboard shows network totals, current approved scope, networks with non-informational findings, assessment count, charts and recent activity. It includes clearly labeled demo data. Mixed-mode WPA counts can overlap. Requiring review indicates configuration risk, not proof of exploitation.

Network discovery defaults to synthetic mode. Confirm authorization; four networks are created and assessed. Repeating a scan appends history, not duplicate networks. Live mode appears only when enabled on the server and needs an approved BSSID and detected monitor-mode interface. Failures remain visible in scan history.

## Inventory and comparison

Search ESSID/BSSID and combine encryption, severity, channel, date/source filters. Date uses last-observed UTC. Pagination retains filters. Open a network to inspect factual configuration, station MACs, history, findings and recommendations. Reassessment evaluates stored facts; it does not perform a fresh radio scan. Select 2–4 currently authorized networks for factual comparison without best/worst rankings.

## Captures

Select an authorized network and upload .cap/.pcap/.pcapng containing matching 802.11 frames. Use LAB-WPA2 with the synthetic sample. The maximum multipart request is 16 MiB, so keep the file slightly smaller. No path components are accepted in filenames.

Results include total/scoped/excluded packets, overlapping protocol counts, BSSID, detected channels, EAPOL/authentication counts and SHA-256. An EAPOL frame also counts as 802.11. A fingerprint identifies the source file without retaining content. EAPOL count is not handshake verification. Ethernet-only or nonmatching files fail. Raw files are removed after normal success or failure.

## Reports and administration

Generate a PDF after selecting a network and confirming permission. The report preserves evidence and rules as they existed then, independent of later changes, and needs authentication to download. Revoked live scopes block new assessments/reports/comparisons while keeping old records available.

Settings records a reference to existing permission, not a substitute for permission. Rule updates apply to new assessments. User deletion disables an account rather than destroying its audit identity. Audit entries include user, action, timestamp and safe details without passwords/payloads.

## Mobile and accessibility

A labeled menu button opens the mobile sidebar. Wide tables scroll inside panels. Inputs have labels, charts have accessible names, and findings include severity text rather than relying on color alone.
