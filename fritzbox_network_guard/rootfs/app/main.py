#!/usr/bin/env python3
"""Prefer main_loader.b64.* (full patched loader), else classic patch pipeline."""
from __future__ import annotations
import base64, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
chunks = sorted(HERE.glob("main_loader.b64.*"))
if chunks:
    code = base64.b64decode("".join(c.read_text().strip() for c in chunks)).decode()
    exec(compile(code, str(HERE / "main_loader_assembled.py"), "exec"), globals())
else:
    # fallback: original pipeline (kept in repo history)
    raise SystemExit("main_loader.b64.* missing")
