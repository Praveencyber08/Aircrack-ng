"""Session authentication, password rotation and CSRF-protected logout."""

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db, limiter
from app.models import User
from app.security import audit

bp = Blueprint("auth", __name__)
DUMMY_HASH = generate_password_hash("unusable-dummy-authentication-value")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")[:64]
        password = request.form.get("password", "")
        if len(password) > 128:
            password = ""
        user = db.session.scalar(db.select(User).filter_by(username=username))
        valid = user.check_password(password) if user else check_password_hash(DUMMY_HASH, password)
        if user and user.active and valid:
            session.clear()
            login_user(user)
            session["version"] = user.session_version
            session.permanent = True
            audit("login", user_id=user.id)
            db.session.commit()
            return redirect(url_for("main.dashboard"))
        audit("login_failed", "Invalid sign-in attempt")
        db.session.commit()
        flash("Invalid username or password.", "danger")
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.post("/logout")
@login_required
def logout():
    audit("logout")
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def change_password():
    if request.method == "POST":
        if not current_user.check_password(request.form.get("current_password", "")[:128]):
            raise ValueError("Current password is incorrect.")
        current_user.set_password(request.form.get("new_password", ""))
        current_user.session_version += 1
        session["version"] = current_user.session_version
        audit("password_changed")
        db.session.commit()
        flash("Password updated; other sessions have been invalidated.", "success")
        return redirect(url_for("main.dashboard"))
    return render_template("password.html")
