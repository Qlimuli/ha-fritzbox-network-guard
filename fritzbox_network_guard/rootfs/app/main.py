#!/usr/bin/env python3
"""Load application: main_full.b64.* chunks, else main_full.gz.b64, else valid parts."""
from __future__ import annotations
import base64
import gzip
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def _load_code() -> str:
    # 1) Chunked full app
    chunks = sorted(HERE.glob("main_full.b64.*"))
    if chunks:
        try:
            b64 = "".join(c.read_text().strip() for c in chunks)
            data = gzip.decompress(base64.b64decode(b64))
            print(f"Assembled main_full from {len(chunks)} chunks ({len(data)} bytes)", file=sys.stderr)
            return data.decode("utf-8")
        except Exception as e:
            print(f"main_full chunks failed: {e}", file=sys.stderr)

    # 2) Single gzip+b64
    full = HERE / "main_full.gz.b64"
    if full.exists():
        try:
            data = gzip.decompress(base64.b64decode(full.read_text().strip()))
            print(f"Loaded main_full.gz.b64 ({len(data)} bytes)", file=sys.stderr)
            return data.decode("utf-8")
        except Exception as e:
            print(f"main_full.gz.b64 failed: {e}", file=sys.stderr)

    # 3) main_part_* – skip invalid base64
    import re
    def num(p):
        m = re.search(r"(\d+)", p.name)
        return int(m.group(1)) if m else 0
    pieces = []
    seen = set()
    for p in sorted(list(HERE.glob("main_part_*.py")) + list(HERE.glob("main_part_*.b64")), key=num):
        n = num(p)
        if n in seen:
            continue
        try:
            if p.suffix == ".py":
                pieces.append((n, p.read_text(encoding="utf-8")))
            else:
                s = p.read_text().strip()
                pad = (4 - len(s) % 4) % 4
                s = s + ("=" * pad)
                pieces.append((n, base64.b64decode(s).decode("utf-8")))
            seen.add(n)
        except Exception as e:
            print(f"skip {p.name}: {e}", file=sys.stderr)
    if pieces:
        pieces.sort(key=lambda x: x[0])
        print(f"Assembled {len(pieces)} main parts (best-effort)", file=sys.stderr)
        return "".join(t for _, t in pieces)

    raise SystemExit("No valid application payload found")

code = _load_code()
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
