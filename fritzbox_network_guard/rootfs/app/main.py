#!/usr/bin/env python3
"""Assemble main_part_*.py or main_part_*.b64 and execute."""
from __future__ import annotations
import base64
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

def _load_code() -> str:
    py_parts = sorted(HERE.glob("main_part_*.py"))
    if py_parts:
        return "".join(p.read_text(encoding="utf-8") for p in py_parts)
    b64_parts = sorted(HERE.glob("main_part_*.b64"))
    if b64_parts:
        return "".join(
            base64.b64decode(p.read_text().strip()).decode("utf-8") for p in b64_parts
        )
    url = (
        "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/"
        "e0455976dbc267320305f80d808a684433ec82f6/"
        "fritzbox_network_guard/rootfs/app/main.py"
    )
    print(f"No main parts – downloading fallback from {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode("utf-8")

code = _load_code()
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
