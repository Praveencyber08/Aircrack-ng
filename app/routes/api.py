"""Session-authenticated REST API; all mutations require a CSRF token."""

from flask import Blueprint, jsonify, request, url_for
from flask_login import login_required
from flask_wtf.csrf import generate_csrf

from app.extensions import db, limiter
from app.models import AuditLog, Finding, Report, Scan
from app.security import SEVERITIES, admin_required, payload
from app.services import workflows as w
from app.services.queries import finding_json, network_json, network_query, paginate

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.before_request
@login_required
def require_login():
    pass


def page_json(page, serializer):
    return jsonify(
        items=[serializer(item) for item in page.items],
        total=page.total,
        page=page.page,
        pages=page.pages,
        per_page=page.per_page,
    )


def scan_json(s):
    return dict(
        id=s.id,
        mode=s.mode,
        status=s.status,
        network_count=s.network_count,
        started_at=s.started_at.isoformat(),
        completed_at=s.completed_at.isoformat() if s.completed_at else None,
        authorized=s.authorized,
        scope_bssid=s.scope_bssid,
        error=s.error,
    )


@bp.get("/csrf-token")
def csrf_token():
    return jsonify(csrf_token=generate_csrf())


@bp.get("/networks")
def networks():
    return page_json(paginate(network_query(request.args)), network_json)


@bp.get("/networks/<int:network_id>")
def network(network_id):
    return jsonify(network_json(w.get_network(network_id), details=True))


@bp.route("/scans", methods=["GET", "POST"])
@limiter.limit("6 per minute", methods=["POST"])
def scans():
    if request.method == "POST":
        return jsonify(scan_json(w.start_scan(payload()))), 201
    return page_json(paginate(db.select(Scan).order_by(Scan.id.desc())), scan_json)


@bp.post("/assessments")
def assessments():
    result = w.start_assessment(payload())
    return jsonify(
        id=result.id,
        network_id=result.network_id,
        findings=[finding_json(f) for f in result.findings],
    ), 201


@bp.post("/captures/analyze")
@limiter.limit("10 per minute")
def capture():
    result = w.analyze_upload(request.form, request.files.get("file"))
    return jsonify(
        id=result.id,
        filename=result.filename,
        size=result.size,
        sha256=result.sha256,
        metadata=result.details,
    ), 201


@bp.get("/findings")
def findings():
    query = db.select(Finding).where(Finding.current.is_(True)).order_by(Finding.id.desc())
    if request.args.get("severity"):
        if request.args["severity"] not in SEVERITIES:
            raise ValueError("Invalid severity.")
        query = query.where(Finding.severity == request.args["severity"])
    return page_json(paginate(query), finding_json)


@bp.get("/reports")
def reports():
    return page_json(
        paginate(db.select(Report).order_by(Report.id.desc())),
        lambda r: dict(
            id=r.id,
            network_id=r.network_id,
            assessment_id=r.assessment_id,
            created_at=r.created_at.isoformat(),
            download_url=url_for("main.report_download", report_id=r.id),
        ),
    )


@bp.post("/reports/generate")
@limiter.limit("10 per minute")
def generate_report():
    report = w.generate_report(payload())
    return jsonify(
        id=report.id, download_url=url_for("main.report_download", report_id=report.id)
    ), 201


@bp.get("/interfaces")
def interfaces():
    return jsonify(items=w.refresh_interfaces())


@bp.get("/audit-logs")
@admin_required
def logs():
    return page_json(
        paginate(db.select(AuditLog).order_by(AuditLog.id.desc())),
        lambda a: dict(
            id=a.id,
            user_id=a.user_id,
            action=a.action,
            detail=a.detail,
            created_at=a.created_at.isoformat(),
        ),
    )
