"""Publish static assets through Vercel's CDN at existing /static URLs."""

from pathlib import Path
from shutil import copytree

root = Path(__file__).resolve().parents[1]
copytree(root / "app" / "static", root / "public" / "static", dirs_exist_ok=True)
