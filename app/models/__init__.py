"""Relational persistence for observations, authorizations and immutable reports."""

from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="analyst")
    active = db.Column(db.Boolean, nullable=False, default=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    @property
    def is_active(self):
        return self.active

    def set_password(self, password):
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise ValueError("Password must contain 12 to 128 characters.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class WirelessInterface(db.Model):
    __tablename__ = "wireless_interfaces"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    mac = db.Column(db.String(17))
    driver = db.Column(db.String(100))
    mode = db.Column(db.String(32))
    status = db.Column(db.String(32))
    monitor_capable = db.Column(db.Boolean, nullable=True)
    observed_at = db.Column(db.DateTime, default=utcnow)


class Scope(db.Model):
    __tablename__ = "scopes"
    id = db.Column(db.Integer, primary_key=True)
    bssid = db.Column(db.String(17), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)
    channel = db.Column(db.Integer, nullable=False)
    permission_reference = db.Column(db.String(200), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mode = db.Column(db.String(16), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="running")
    interface = db.Column(db.String(32))
    scope_bssid = db.Column(db.String(17))
    scope_reference = db.Column(db.String(200))
    authorized = db.Column(db.Boolean, nullable=False)
    started_at = db.Column(db.DateTime, default=utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    error = db.Column(db.String(300))
    network_count = db.Column(db.Integer, default=0)
    observations = db.relationship("Observation", back_populates="scan")


class Network(db.Model):
    __tablename__ = "networks"
    __table_args__ = (db.UniqueConstraint("bssid", "demo"),)
    id = db.Column(db.Integer, primary_key=True)
    essid = db.Column(db.String(128), nullable=False)
    bssid = db.Column(db.String(17), nullable=False, index=True)
    channel = db.Column(db.Integer, index=True)
    encryption = db.Column(db.String(64), index=True)
    cipher = db.Column(db.String(64))
    authentication = db.Column(db.String(64))
    signal = db.Column(db.Integer)
    stations = db.Column(db.JSON, default=list)
    demo = db.Column(db.Boolean, nullable=False, default=False, index=True)
    first_seen = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow, index=True)
    findings = db.relationship("Finding", back_populates="network", cascade="all, delete-orphan")
    observations = db.relationship("Observation", back_populates="network")
    assessments = db.relationship("Assessment", back_populates="network")


class Observation(db.Model):
    __tablename__ = "observations"
    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey("networks.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    observed_at = db.Column(db.DateTime, default=utcnow)
    facts = db.Column(db.JSON, nullable=False)
    network = db.relationship("Network", back_populates="observations")
    scan = db.relationship("Scan", back_populates="observations")


class Assessment(db.Model):
    __tablename__ = "assessments"
    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey("networks.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    authorized = db.Column(db.Boolean, nullable=False)
    scope_reference = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    evidence = db.Column(db.JSON, nullable=False)
    rules = db.Column(db.JSON, nullable=False)
    network = db.relationship("Network", back_populates="assessments")
    findings = db.relationship("Finding", back_populates="assessment")


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey("networks.id"), nullable=False, index=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id"), nullable=False, index=True
    )
    title = db.Column(db.String(160), nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=False)
    impact = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    current = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    network = db.relationship("Network", back_populates="findings")
    assessment = db.relationship("Assessment", back_populates="findings")


class Capture(db.Model):
    __tablename__ = "captures"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(180), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    network_id = db.Column(db.Integer, db.ForeignKey("networks.id"), nullable=False)
    authorized = db.Column(db.Boolean, nullable=False)
    details = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    network = db.relationship("Network")


class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    network_id = db.Column(db.Integer, db.ForeignKey("networks.id"), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    filename = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    network = db.relationship("Network")
    assessment = db.relationship("Assessment")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    detail = db.Column(db.String(300), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    user = db.relationship("User")


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.JSON, nullable=False)
