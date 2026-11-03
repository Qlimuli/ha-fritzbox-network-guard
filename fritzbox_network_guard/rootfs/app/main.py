#!/usr/bin/env python3
"""Assemble main_part_*.py / main_part_*.b64 (sorted) and execute."""
from __future__ import annotations
import base64
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

def _num(p: Path) -> int:
    m = re.search(r"(\d+)", p.name)
    return int(m.group(1)) if m else 0

def _load_code() -> str:
    pieces: list[tuple[int, str]] = []
    for p in HERE.glob("main_part_*.py"):
        pieces.append((_num(p), p.read_text(encoding="utf-8")))
    for p in HERE.glob("main_part_*.b64"):
        pieces.append((_num(p), base64.b64decode(p.read_text().strip()).decode("utf-8")))
    if not pieces:
        url = (
            "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/"
            "e0455976dbc267320305f80d808a684433ec82f6/"
            "fritzbox_network_guard/rootfs/app/main.py"
        )
        print(f"No main parts – downloading fallback", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read().decode("utf-8")
    pieces.sort(key=lambda x: x[0])
    print(f"Assembled {len(pieces)} main parts", file=sys.stderr)
    return "".join(t for _, t in pieces)

code = _load_code()
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
