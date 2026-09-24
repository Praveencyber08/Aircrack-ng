# Security model

## Scope

Every scan, assessment, capture analysis and report requires explicit confirmation of ownership/permission. User, time, selected network/scope and confirmation are recorded. Live operations additionally require administrator-approved BSSIDs; demo uses a separate synthetic scope.

No cracking, credential recovery, deauthentication, injection, persistence or evasion is implemented. Aircrack suite integration is limited to passive airodump CSV, read-only airmon listing and fixed aircrack help diagnostics. Aireplay is not invoked.

| Threat | Control | Residual limit |
|---|---|---|
| Password disclosure | Scrypt hashes | Protect database/backups |
| Session misuse | Signed, HttpOnly, SameSite Strict cookies; expiry and version revocation | Enable Secure only behind HTTPS |
| CSRF | Flask-WTF on all mutations, including API/login/logout | Reload expired forms |
| SQL injection | Bound SQLAlchemy expressions and literal LIKE escaping | DB admins retain direct access |
| XSS | Jinja escaping, PDF XML escaping, script CSP | Inline styles remain permitted for UI libraries |
| Command injection | Fixed executables, arrays, strict input validation | Trust installed binaries and PATH |
| Out-of-scope activity | Scope check plus BSSID filter and post-parse filtering | BSSIDs can be spoofed |
| Upload traversal | Reject separators; generated private paths | Secure directory ownership |
| Parser abuse | Framing checks, 16 MiB, 100k packets, deadline, Linux resource limits | Same OS identity, not full sandbox |
| Credential retention | No payload serialization; temporary file cleanup | Raw upload exists briefly during analysis |
| Resource abuse | IP-based rate limits | Default counters reset per process |
| Report tampering | Preserved snapshots and authenticated downloads | No digital signature |
| Audit tampering | No API to rewrite events | Local DB administrators can modify files |

## Data minimization

No Wi-Fi password fields exist. Metadata contains counts, selected BSSID, channels/protocols and fingerprint. Obtain permission before acquiring or uploading captures; filtering is not permission to upload third-party data. Probe-request ESSID lists and packet bytes are not persisted. AP names/BSSIDs and station MACs are lab metadata that still deserve access controls.

PDF fonts support Latin-1; unsupported characters become `?` while web pages retain Unicode. Normal completion/error cleanup removes raw uploads and scan files. OS/process crashes can leave temporary files: stop the service, inspect job directories, and remove only stale files within the configured upload directory. Secure erasure from storage/backups is not guaranteed.

## Operating boundaries

Use loopback on a dedicated, unprivileged small-lab server. Grant radio capabilities only to a trusted airodump binary when appropriate, never to the Python interpreter or whole web server. Lab users share the inventory; this is not multi-tenant isolation. Serialize live operations on each adapter. Keep deployed code and vendor files protected from untrusted writes.

Historical reports remain after scope revocation. The generated first-login file is local and ignored; change the password and remove it. Instance data, .env, captured files and private outputs are excluded from Git. Audit events are application-append-only, not cryptographically tamper-evident.

## References

- [Flask security](https://flask.palletsprojects.com/en/stable/web-security/)
- [Flask-WTF CSRF](https://flask-wtf.readthedocs.io/en/stable/csrf/)
- [Airodump-ng](https://www.aircrack-ng.org/doku.php?id=airodump-ng)
- [Scapy wireless layers](https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html)
