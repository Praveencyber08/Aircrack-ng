# Database schema and retention

Models in app/models/__init__.py are the schema source of truth. The default SQLite database lives in ignored instance storage. Initialize with `flask --app app:create_app init-db`.

| Table | Purpose |
|---|---|
| users | Unique username, scrypt hash, role, active/session version |
| wireless_interfaces | Latest hardware observations |
| scopes | Approved BSSID, channel, permission and creator |
| scans | User, authorization, scope snapshot and lifecycle |
| networks | Unique BSSID/demo, latest configuration |
| observations | Network/scan and immutable JSON facts |
| assessments | Network/user, confirmation, evidence/rule snapshots |
| findings | Assessment/network, severity/evidence/impact/recommendation/current flag |
| captures | Network/user, confirmation, hash and metadata only |
| reports | Network/assessment/user and private PDF filename |
| audit_logs | User, action, safe detail and UTC time |
| settings | Rule configuration |

Foreign keys are enforced. Historical records remain until an administrator applies a documented retention policy offline. Soft-deleted users preserve attribution. No app endpoint rewrites/deletes audit history. Back up SQLite and PDFs together while stopped. Never commit DB, credentials or local signing keys.
