# Installation

## Environment

Python 3.11+ is required; this workspace was validated with Python 3.14 on Windows. Demo, capture analysis, database and PDFs need no adapter. Live scanning requires Kali/Linux, Aircrack-ng, iw and a monitor-capable adapter. A VM normally needs USB passthrough; virtual Ethernet cannot provide 802.11 monitor frames.

## Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip aircrack-ng iw
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python -m flask --app app:create_app init-db
python -m flask --app app:create_app create-admin
aircrack-ng --help
airmon-ng
iw dev
waitress-serve --listen=127.0.0.1:5000 --threads=4 --call app:create_app
```

Run from the project root. Initialization creates tables without dropping data. Choose a unique application password of 12–128 characters. This is distinct from any Wi-Fi passphrase. Visit http://127.0.0.1:5000. Some tool versions return nonzero status for help; diagnostics report this without treating it as scan evidence.

Keep debug off and do not run the web server as root. The scanner inherits existing radio permissions; see lab-setup.md for dedicated-host capability provisioning. The app does not accept sudo passwords.

## Windows demo

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python -m flask --app app:create_app init-db
.\.venv\Scripts\python -m flask --app app:create_app create-admin
.\.venv\Scripts\python -m waitress --listen=127.0.0.1:5000 --threads=4 --call app:create_app
```

Alternatively, `python scripts/prepare_local_demo.py` creates `demo-admin` with a random password in an ignored local file, without changing existing accounts. Remove that file after changing the password.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| SECRET_KEY | Locally generated | Session/CSRF signing, at least 32 characters |
| DATABASE_URL | sqlite:///wifi_guard.sqlite | SQLite paths relative to Flask instance |
| REPORT_DIR | instance/reports | Private PDF output |
| UPLOAD_DIR | instance/uploads | Temporary analysis storage |
| DEMO_MODE | true | Synthetic operations available |
| ENABLE_LIVE_SCAN | false | Scoped live discovery permitted |
| COOKIE_SECURE | false | Enable with HTTPS only |
| RATELIMIT_STORAGE_URI | memory:// | Per-process counters |

Upload/report relative paths resolve from the project root. Keep private files outside static assets. Sessions expire after 30 minutes of inactivity; CSRF tokens after an hour. Changing the signing secret invalidates sessions. Restrict Windows ACLs on private directories when sharing a machine; POSIX creation modes do not configure Windows ACLs.

## Hosting, backup and upgrades

Loopback is the documented deployment. A remote lab needs TLS, secure cookies, trusted reverse-proxy configuration and shared rate limiting for multiple processes. Internet-facing production deployment is not validated. Stop the service before backing up SQLite, reports and the local secret together. Protect backups as sensitive lab records. This initial release has no migration framework: `create_all` creates missing tables, not schema migrations.
