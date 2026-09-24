"""Environment configuration; secrets are never supplied by the repository."""

import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///wifi_guard.sqlite")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    REPORT_DIR = os.getenv("REPORT_DIR", "instance/reports")
    UPLOAD_DIR = os.getenv("UPLOAD_DIR", "instance/uploads")
    DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
    ENABLE_LIVE_SCAN = os.getenv("ENABLE_LIVE_SCAN", "false").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    CAPTURE_TIMEOUT = 30
    CAPTURE_PACKET_LIMIT = 100000
