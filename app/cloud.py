"""Explicit, disposable cloud demo configuration."""

import os
import re
import tempfile
from pathlib import Path


def cloud_config():
    if os.getenv("VERCEL") != "1":
        return None
    if os.getenv("CLOUD_DEMO", "").lower() != "true":
        raise RuntimeError("Set CLOUD_DEMO=true to run the disposable Vercel demonstration.")
    secret = os.getenv("SECRET_KEY", "")
    username = os.getenv("DEMO_ADMIN_USERNAME", "")
    password = os.getenv("DEMO_ADMIN_PASSWORD", "")
    if len(secret) < 32:
        raise RuntimeError("Set SECRET_KEY to a random value of at least 32 characters in Vercel.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise RuntimeError("Set DEMO_ADMIN_USERNAME to 3-64 letters, numbers, dots or hyphens.")
    if not 12 <= len(password) <= 128:
        raise RuntimeError("Set DEMO_ADMIN_PASSWORD to a private password of 12-128 characters.")
    root = Path(tempfile.mkdtemp(prefix="spectra-demo-"))
    return root, {
        "SECRET_KEY": secret,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + (root / "demo.sqlite").as_posix(),
        "REPORT_DIR": str(root / "reports"),
        "UPLOAD_DIR": str(root / "uploads"),
        "DEMO_MODE": True,
        "ENABLE_LIVE_SCAN": False,
        "SESSION_COOKIE_SECURE": True,
        "CLOUD_DEMO": True,
    }


def initialize_cloud_demo(app):
    from app.extensions import db
    from app.models import User

    with app.app_context():
        db.create_all()
        user = User(username=os.environ["DEMO_ADMIN_USERNAME"], role="admin")
        user.set_password(os.environ["DEMO_ADMIN_PASSWORD"])
        db.session.add(user)
        db.session.commit()
