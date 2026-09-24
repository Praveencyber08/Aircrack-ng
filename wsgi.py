"""WSGI entry point for hosting providers."""

from app import create_app

app = create_app()
