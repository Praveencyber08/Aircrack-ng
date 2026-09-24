"""Validation and role checks shared by HTML and JSON endpoints."""

import re
from functools import wraps

from flask import abort, request
from flask_login import current_user

from app.extensions import db
from app.models import AuditLog

AUTHORIZATION = "I confirm that I own this network or have explicit authorization to perform this security assessment."
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]


def admin_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return func(*args, **kwargs)

    return wrapped


def audit(action, detail="", user_id=None):
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    db.session.add(AuditLog(user_id=user_id, action=action, detail=detail[:300]))


def payload():
    if request.is_json:
        data = request.get_json()
        if not isinstance(data, dict):
            raise ValueError("A JSON object is required.")
        return data
    return request.form


def confirmed(data):
    if data.get("authorized") not in (True, "on", "true"):
        raise ValueError("Explicit authorization confirmation is required.")


def integer(value, name, low=1, high=2147483647):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError(f"{name} must be an integer.")
    number = int(value)
    if not low <= number <= high:
        raise ValueError(f"{name} must be between {low} and {high}.")
    return number


def mac(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value
    ):
        raise ValueError("A valid colon-separated BSSID is required.")
    result = value.upper()
    if int(result[:2], 16) & 1 or result == "00:00:00:00:00:00":
        raise ValueError("A unicast BSSID is required.")
    return result


def text_field(value, name, maximum=100):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{name} is required (maximum {maximum} characters).")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"{name} contains invalid control characters.")
    return value.strip()
