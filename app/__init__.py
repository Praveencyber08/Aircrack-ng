"""Application factory and safe CLI provisioning."""

import secrets
import sqlite3
from pathlib import Path

import click
from flask import Flask, jsonify, render_template, request, session
from flask_login import current_user
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.exceptions import HTTPException

from app.extensions import csrf, db, limiter, login_manager
from app.models import AuditLog, User
from config import Config


@event.listens_for(Engine, "connect")
def sqlite_constraints(connection, record):
    if isinstance(connection, sqlite3.Connection):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")


def create_app(test_config=None):
    from app.cloud import cloud_config, initialize_cloud_demo

    cloud = cloud_config() if test_config is None else None
    instance_options = {"instance_path": str(cloud[0])} if cloud else {}
    app = Flask(__name__, instance_relative_config=True, **instance_options)
    app.config.from_object(Config)
    if cloud:
        app.config.update(cloud[1])
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config.get("SECRET_KEY"):
        # Local secret is generated once with restrictive creation permissions.
        secret_path = Path(app.instance_path) / ".secret_key"
        try:
            fd = __import__("os").open(
                str(secret_path),
                __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_EXCL,
                0o600,
            )
            with __import__("os").fdopen(fd, "w") as handle:
                handle.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        app.config["SECRET_KEY"] = secret_path.read_text().strip()
    if len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters.")
    for key in ("REPORT_DIR", "UPLOAD_DIR"):
        path = Path(app.config[key])
        if not path.is_absolute():
            path = Path(app.root_path).parent / path
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        app.config[key] = str(path.resolve())
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = db.session.get(User, int(user_id))
        except ValueError:
            return None
        if not user or not user.active or session.get("version") != user.session_version:
            return None
        return user

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication required."), 401
        from flask import redirect, url_for

        return redirect(url_for("auth.login"))

    @app.before_request
    def session_lifetime():
        if current_user.is_authenticated:
            session.permanent = True

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        db.session.rollback()
        if isinstance(exc, HTTPException):
            code, message = exc.code, exc.description
        elif isinstance(exc, ValueError):
            code, message = 400, str(exc)
        else:
            from scanners.aircrack_wrapper import ToolError

            if isinstance(exc, ToolError):
                code, message = 503, str(exc)
            else:
                code, message = 500, "An unexpected error occurred. Contact the lab administrator."
                app.logger.error("Unhandled application error: %s", type(exc).__name__)
        if request.path.startswith("/api/"):
            return jsonify(error=message), code
        return render_template("error.html", code=code, message=message), code

    from app.routes.api import bp as api_bp
    from app.routes.auth import bp as auth_bp
    from app.routes.main import bp as main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def shared():
        from app.security import AUTHORIZATION, SEVERITIES

        return dict(
            authorization_text=AUTHORIZATION,
            severities=SEVERITIES,
            demo_enabled=app.config["DEMO_MODE"],
            live_enabled=app.config["ENABLE_LIVE_SCAN"],
        )

    @app.cli.command("init-db")
    def init_db():
        """Create tables without deleting existing data."""
        db.create_all()
        click.echo("Database initialized.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.password_option()
    def create_admin(username, password):
        """Create an administrator using a hidden password prompt."""
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise click.ClickException(
                "Username must be 3-64 letters, numbers, dots, underscores or hyphens."
            )
        if db.session.scalar(db.select(User).filter_by(username=username)):
            raise click.ClickException("Username already exists.")
        user = User(username=username, role="admin")
        try:
            user.set_password(password)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        db.session.add(user)
        db.session.flush()
        db.session.add(
            AuditLog(
                user_id=user.id,
                action="user_created",
                detail="Administrator created through local CLI",
            )
        )
        db.session.commit()
        click.echo("Administrator created. Sign in and run an authorized demo discovery.")

    if cloud:
        initialize_cloud_demo(app)
    return app
