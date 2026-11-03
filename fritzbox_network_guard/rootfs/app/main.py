#!/usr/bin/env python3
"""Assemble main_part_*.py (or download fallback) and execute."""
from __future__ import annotations
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
parts = sorted(HERE.glob("main_part_*.py"))
if parts:
    code = "\n".join(p.read_text(encoding="utf-8") for p in parts)
    exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
else:
    url = (
        "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/"
        "e0455976dbc267320305f80d808a684433ec82f6/"
        "fritzbox_network_guard/rootfs/app/main.py"
    )
    print(f"No main_part_*.py – downloading fallback from {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as r:
        code = r.read().decode("utf-8")
    exec(compile(code, "main_fallback.py", "exec"), globals())
