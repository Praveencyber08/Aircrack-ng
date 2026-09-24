"""Provision a local demo with a random initial administrator password.

The ignored first-login file is created with owner-only permissions on POSIX.
Change the password and remove this file after first sign-in.
"""

import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app
from app.extensions import db
from app.models import AuditLog, User

app = create_app()
with app.app_context():
    db.create_all()
    if db.session.scalar(db.select(User).filter_by(username="demo-admin")):
        print("demo-admin already exists; its password was not changed.")
    else:
        password = secrets.token_urlsafe(20)
        user = User(username="demo-admin", role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        db.session.add(
            AuditLog(
                user_id=user.id,
                action="user_created",
                detail="Local demo administrator provisioned",
            )
        )
        location = Path(app.instance_path) / "first-login.txt"
        fd = os.open(location, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(
                "Username: demo-admin\nPassword: "
                + password
                + "\n\nChange this password after first sign-in and delete this file.\n"
            )
        db.session.commit()
        print("Local credentials saved in instance/first-login.txt (ignored by Git).")
