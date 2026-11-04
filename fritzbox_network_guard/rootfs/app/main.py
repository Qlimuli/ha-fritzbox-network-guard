#!/usr/bin/env python3
"""Assemble v2 modules from gzip+b64 chunks, then run main application."""
from __future__ import annotations
import base64, gzip, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def assemble(prefix: str, dest: str) -> None:
    chunks = sorted(HERE.glob(f"{prefix}.b64.*"))
    if not chunks:
        return
    b64 = "".join(c.read_text().strip() for c in chunks)
    data = gzip.decompress(base64.b64decode(b64))
    (HERE / dest).write_bytes(data)
    print(f"assembled {dest} ({len(data)} bytes)", file=sys.stderr)

for prefix, dest in [
    ("v2_state", "state.py"),
    ("v2_fritz", "fritz_client.py"),
    ("v2_discovery", "discovery.py"),
    ("v2_ha", "ha_integration.py"),
    ("v2_ui", "ui.html"),
    ("v2_main", "main_app.py"),
]:
    try:
        assemble(prefix, dest)
    except Exception as e:
        print(f"assemble {prefix} failed: {e}", file=sys.stderr)

app = HERE / "main_app.py"
if not app.exists():
    raise SystemExit("main_app.py missing after assemble")
code = app.read_text(encoding="utf-8")
exec(compile(code, str(app), "exec"), {"__name__": "__main__", "__file__": str(app)})
