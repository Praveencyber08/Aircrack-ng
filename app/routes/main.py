"""Authenticated HTML views and administrator operations."""

import re
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db, limiter
from app.models import AuditLog, Capture, Finding, Network, Report, Scan, Scope, Setting, User
from app.security import SEVERITIES, admin_required, audit, integer, mac, text_field
from app.services import workflows as w
from app.services.queries import dashboard_data, network_query, paginate
from scanners.aircrack_wrapper import AircrackWrapper

bp = Blueprint("main", __name__)


@bp.before_request
@login_required
def require_login():
    pass


@bp.get("/")
def dashboard():
    return render_template("dashboard.html", stats=dashboard_data())


@bp.route("/discovery", methods=["GET", "POST"])
@limiter.limit("6 per minute", methods=["POST"])
def discovery():
    if request.method == "POST":
        scan = w.start_scan(request.form)
        flash(
            f"Scan #{scan.id} completed: {scan.network_count} networks observed and assessed.",
            "success",
        )
        return redirect(url_for("main.networks"))
    return render_template(
        "discovery.html",
        scopes=db.session.scalars(db.select(Scope)).all(),
        scans=paginate(db.select(Scan).order_by(Scan.id.desc())),
        interfaces=w.detect_interfaces(),
    )


@bp.get("/interfaces")
def interfaces():
    return render_template(
        "interfaces.html",
        interfaces=w.refresh_interfaces(),
        diagnostics=AircrackWrapper().diagnostics(),
    )


@bp.get("/networks")
def networks():
    return render_template("networks.html", pagination=paginate(network_query(request.args)))


@bp.get("/networks/<int:network_id>")
def network_detail(network_id):
    network = w.get_network(network_id)
    return render_template(
        "network.html",
        network=network,
        in_scope=w.allowed(network),
        findings=[f for f in network.findings if f.current],
        history=sorted(network.observations, key=lambda o: o.id, reverse=True)[:50],
    )


@bp.post("/assessments")
def assess():
    record = w.start_assessment(request.form)
    flash("Assessment completed from the latest observed configuration.", "success")
    return redirect(url_for("main.network_detail", network_id=record.network_id))


@bp.get("/findings")
def findings():
    query = db.select(Finding).where(Finding.current.is_(True)).order_by(Finding.id.desc())
    severity = request.args.get("severity")
    if severity:
        if severity not in SEVERITIES:
            raise ValueError("Invalid severity.")
        query = query.where(Finding.severity == severity)
    return render_template("findings.html", pagination=paginate(query))


@bp.route("/captures", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def captures():
    if request.method == "POST":
        record = w.analyze_upload(request.form, request.files.get("file"))
        flash(f"Capture #{record.id} analyzed. The raw file has been deleted.", "success")
        return redirect(url_for("main.captures"))
    return render_template(
        "captures.html",
        pagination=paginate(db.select(Capture).order_by(Capture.id.desc())),
        networks=[n for n in db.session.scalars(db.select(Network)) if w.allowed(n)],
    )


@bp.route("/reports", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def reports():
    if request.method == "POST":
        record = w.generate_report(request.form)
        flash(f"Report #{record.id} generated with an immutable evidence snapshot.", "success")
        return redirect(url_for("main.reports"))
    return render_template(
        "reports.html",
        pagination=paginate(db.select(Report).order_by(Report.id.desc())),
        networks=[n for n in db.session.scalars(db.select(Network)) if w.allowed(n)],
    )


@bp.get("/reports/<int:report_id>/download")
def report_download(report_id):
    report = db.get_or_404(Report, report_id)
    root = Path(current_app.config["REPORT_DIR"]).resolve()
    path = (root / report.filename).resolve()
    if path.parent != root or not path.is_file():
        abort(404)
    return send_file(
        path,
        as_attachment=True,
        download_name=f"wifi-assessment-{report.id}.pdf",
        mimetype="application/pdf",
    )


@bp.get("/compare")
def compare():
    ids = request.args.getlist("id")
    if not 2 <= len(ids) <= 4:
        raise ValueError("Select between two and four authorized networks to compare.")
    networks = [w.get_network(i, require_scope=True) for i in dict.fromkeys(ids)]
    if len(networks) < 2:
        raise ValueError("Select distinct networks.")
    return render_template("compare.html", networks=networks)


@bp.get("/audit-logs")
@admin_required
def audit_logs():
    return render_template(
        "audit.html", pagination=paginate(db.select(AuditLog).order_by(AuditLog.id.desc()))
    )


@bp.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        username = request.form.get("username", "")
        role = request.form.get("role", "analyst")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username) or role not in ("admin", "analyst"):
            raise ValueError("Invalid username or role.")
        if db.session.scalar(db.select(User).filter_by(username=username)):
            raise ValueError("Username already exists.")
        user = User(username=username, role=role)
        user.set_password(request.form.get("password", ""))
        db.session.add(user)
        db.session.flush()
        audit("user_created", f"User {user.id}; role {role}")
        db.session.commit()
        flash("User created.", "success")
        return redirect(url_for("main.users"))
    return render_template(
        "users.html", users=db.session.scalars(db.select(User).order_by(User.id)).all()
    )


@bp.post("/users/<int:user_id>/delete")
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        raise ValueError("You cannot delete your own account.")
    user = db.get_or_404(User, user_id)
    # Soft deletion preserves foreign keys and historical attribution.
    user.active = False
    user.session_version += 1
    audit("user_deleted", f"User {user.id}; access revoked, history retained")
    db.session.commit()
    flash("User access revoked. Historical audit records are retained.", "success")
    return redirect(url_for("main.users"))


@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "scope":
            bssid = mac(request.form.get("bssid"))
            if db.session.scalar(db.select(Scope).filter_by(bssid=bssid)):
                raise ValueError("This BSSID already has an approved scope.")
            scope = Scope(
                bssid=bssid,
                channel=integer(request.form.get("channel"), "Channel", 1, 233),
                label=text_field(request.form.get("label"), "Lab label"),
                permission_reference=text_field(
                    request.form.get("permission_reference"), "Permission reference", 200
                ),
                created_by=current_user.id,
            )
            db.session.add(scope)
            audit("configuration_changed", f"Approved scope {bssid}")
        elif action == "rules":
            values = {key: request.form.get(key) for key in w.DEFAULT_RULES}
            if any(value not in SEVERITIES for value in values.values()):
                raise ValueError("Every rule requires a valid severity.")
            setting = db.session.get(Setting, "risk_rules")
            if setting:
                setting.value = values
            else:
                db.session.add(Setting(key="risk_rules", value=values))
            audit(
                "configuration_changed",
                "Assessment severity rules updated; existing assessments retained",
            )
        else:
            raise ValueError("Unknown settings operation.")
        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("main.settings"))
    return render_template(
        "settings.html", scopes=db.session.scalars(db.select(Scope)).all(), rules=w.rules()
    )


@bp.post("/scopes/<int:scope_id>/delete")
@admin_required
def revoke_scope(scope_id):
    scope = db.get_or_404(Scope, scope_id)
    audit("configuration_changed", f"Revoked scope {scope.bssid}")
    db.session.delete(scope)
    db.session.commit()
    flash("Scope revoked. Historical observations and reports remain available.", "success")
    return redirect(url_for("main.settings"))
