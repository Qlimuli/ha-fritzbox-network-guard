#!/usr/bin/env python3
"""Assemble application code and execute.

Order:
  1. main_part_*.py / main_part_*.b64 (sorted by number) if present
  2. main_full.gz.b64 (gzip+base64 of full main.py)
  3. Fallback download from known good commit
"""
from __future__ import annotations
import base64
import gzip
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
    if pieces:
        pieces.sort(key=lambda x: x[0])
        seen = set()
        ordered = []
        for n, t in pieces:
            if n in seen:
                continue
            seen.add(n)
            ordered.append(t)
        print(f"Assembled {len(ordered)} main parts", file=sys.stderr)
        return "".join(ordered)

    full = HERE / "main_full.gz.b64"
    if full.exists():
        data = gzip.decompress(base64.b64decode(full.read_text().strip()))
        print(f"Loaded main_full.gz.b64 ({len(data)} bytes)", file=sys.stderr)
        return data.decode("utf-8")

    url = (
        "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/"
        "main/fritzbox_network_guard/rootfs/app/main_full.gz.b64"
    )
    print("No main parts – downloading main_full.gz.b64 fallback", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as r:
        data = gzip.decompress(base64.b64decode(r.read()))
        return data.decode("utf-8")


code = _load_code()
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
