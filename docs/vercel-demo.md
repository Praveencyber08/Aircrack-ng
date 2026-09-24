# Vercel college demonstration

This deployment is an explicitly enabled, disposable demonstration, not persistent hosting.
Each function process has its own temporary database and reports. Data, account changes,
password changes and reports can disappear or differ between instances. The bootstrap
account is recreated from environment variables. Use synthetic demo discovery only.
Live radio scanning is disabled. Use the local Linux installation for hardware testing.

## Deploy

1. Upload the updated source files, including app/cloud.py, app/__init__.py,
   app/templates/base.html, scripts/build_vercel.py, pyproject.toml, wsgi.py,
   .python-version and .vercelignore to the GitHub repository.
2. In Vercel Project Settings > Environment Variables, set these for the deployment:
   - CLOUD_DEMO: true
   - SECRET_KEY: a random secret of at least 32 characters
   - DEMO_ADMIN_USERNAME: your chosen username (3-64 letters/numbers/._-)
   - DEMO_ADMIN_PASSWORD: your private password (12-128 characters)
3. Generate SECRET_KEY locally using:
   `python -c "import secrets; print(secrets.token_hex(32))"`
   Paste it into Vercel, never into source code or a public message.
4. Use the Flask framework preset. Leave the Build Command override disabled so
   pyproject.toml runs `python scripts/build_vercel.py`. Leave Output Directory unset.
5. Redeploy. Sign in with the two DEMO_ADMIN values. Run an authorized demo discovery
   to populate the dashboard with synthetic networks.

The build copies CSS and JavaScript to public/static for Vercel CDN delivery.
VERCEL=1 is supplied by Vercel. Do not set it for normal local use.
Existing DATABASE_URL, REPORT_DIR and UPLOAD_DIR values are ignored in cloud demo mode
to isolate the demonstration from any persistent database or local data.

For durable hosting, implement a shared database, shared report storage and distributed
rate limiting instead of using this temporary demo configuration.

If startup still fails, open Runtime Logs and inspect the Python traceback. A generic
FUNCTION_INVOCATION_FAILED screenshot alone does not identify the underlying exception.

References: https://vercel.com/docs/frameworks/backend/flask and
https://vercel.com/docs/functions/runtimes/python
