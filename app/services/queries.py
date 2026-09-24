"""Filtering, serialization and dashboard aggregates."""

from collections import Counter
from datetime import datetime, timedelta

from flask import request

from app.extensions import db
from app.models import Assessment, Finding, Network, Report, Scan
from app.security import SEVERITIES, integer
from app.services.workflows import allowed, network_facts


def network_query(args):
    query = db.select(Network)
    search = args.get("q", "").strip()
    if len(search) > 128:
        raise ValueError("Search is too long.")
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(
            db.or_(
                Network.essid.ilike(f"%{escaped}%", escape="\\"),
                Network.bssid.ilike(f"%{escaped}%", escape="\\"),
            )
        )
    if args.get("encryption"):
        query = query.where(Network.encryption == args["encryption"][:64])
    if args.get("channel"):
        query = query.where(Network.channel == integer(args["channel"], "Channel", 1, 233))
    if args.get("severity"):
        if args["severity"] not in SEVERITIES:
            raise ValueError("Invalid severity.")
        query = query.where(
            Network.findings.any(
                db.and_(Finding.current.is_(True), Finding.severity == args["severity"])
            )
        )
    if args.get("date"):
        try:
            date = datetime.strptime(args["date"], "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("Date must be YYYY-MM-DD.") from exc
        query = query.where(Network.last_seen >= date, Network.last_seen < date + timedelta(days=1))
    if args.get("source") in ("demo", "live"):
        query = query.where(Network.demo.is_(args["source"] == "demo"))
    return query.order_by(Network.last_seen.desc(), Network.id)


def paginate(query, args=None):
    args = args if args is not None else request.args
    page = integer(args.get("page", 1), "Page", 1, 100000)
    per_page = integer(args.get("per_page", 12), "Page size", 1, 100)
    return db.paginate(query, page=page, per_page=per_page, error_out=False)


def finding_json(f):
    return {
        key: getattr(f, key)
        for key in (
            "id",
            "network_id",
            "assessment_id",
            "title",
            "severity",
            "description",
            "evidence",
            "impact",
            "recommendation",
            "current",
        )
    }


def network_json(n, details=False):
    result = {
        "id": n.id,
        **network_facts(n),
        "authorized": allowed(n),
        "first_seen": n.first_seen.isoformat(),
        "last_seen": n.last_seen.isoformat(),
        "stations": n.stations,
        "findings": [finding_json(f) for f in n.findings if f.current],
    }
    if details:
        result["history"] = [
            {"scan_id": o.scan_id, "observed_at": o.observed_at.isoformat(), "facts": o.facts}
            for o in n.observations
        ]
    return result


def dashboard_data():
    networks = list(db.session.scalars(db.select(Network)))
    findings = list(db.session.scalars(db.select(Finding).where(Finding.current.is_(True))))
    severity = Counter(f.severity for f in findings)
    channels = Counter(str(n.channel) for n in networks)
    return dict(
        total=len(networks),
        authorized=sum(allowed(n) for n in networks),
        open_count=sum(n.encryption in ("OPN", "OPEN") for n in networks),
        wpa=sum("WPA" in (n.encryption or "").split() for n in networks),
        wpa2=sum("WPA2" in (n.encryption or "") for n in networks),
        wpa3=sum("WPA3" in (n.encryption or "") for n in networks),
        review=len({f.network_id for f in findings if f.severity != "Informational"}),
        demo_count=sum(n.demo for n in networks),
        assessments=db.session.scalar(db.select(db.func.count(Assessment.id))),
        severity={s: severity[s] for s in SEVERITIES},
        channels=dict(channels),
        scans=list(db.session.scalars(db.select(Scan).order_by(Scan.id.desc()).limit(5))),
        reports=list(db.session.scalars(db.select(Report).order_by(Report.id.desc()).limit(5))),
    )
