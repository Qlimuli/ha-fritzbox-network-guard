#!/usr/bin/env python3
"""Bootstrap: load known-good main from GitHub if local payload missing."""
from __future__ import annotations

import base64
import gzip
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "_main_impl.py"

# Prefer compressed local payload if present and valid
def _try_local_b64() -> bool:
    p = HERE / "main.py.gz.b64"
    if not p.exists():
        return False
    try:
        data = gzip.decompress(base64.b64decode(p.read_text().strip().encode()))
        TARGET.write_bytes(data)
        return True
    except Exception as exc:
        print(f"local b64 failed: {exc}", file=sys.stderr)
        return False

def _download_good() -> None:
    # Known-good 1.3.4 main.py
    url = (
        "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/"
        "e0455976dbc267320305f80d808a684433ec82f6/"
        "fritzbox_network_guard/rootfs/app/main.py"
    )
    print(f"Downloading fallback main from {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as r:
        TARGET.write_bytes(r.read())

if not TARGET.exists() or TARGET.stat().st_size < 1000:
    if not _try_local_b64():
        _download_good()

code = TARGET.read_text(encoding="utf-8")
exec(compile(code, str(TARGET), "exec"), globals())
