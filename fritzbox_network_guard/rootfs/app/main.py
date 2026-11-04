#!/usr/bin/env python3
"""Load application from main_full.b64.* chunks (production payload)."""
from __future__ import annotations
import base64
import gzip
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def _load_code() -> str:
    chunks = sorted(HERE.glob("main_full.b64.*"))
    if chunks:
        try:
            b64 = "".join(c.read_text().strip() for c in chunks)
            data = gzip.decompress(base64.b64decode(b64))
            print(f"Assembled main_full from {len(chunks)} chunks ({len(data)} bytes)", file=sys.stderr)
            return data.decode("utf-8")
        except Exception as e:
            print(f"main_full chunks failed: {e}", file=sys.stderr)

    full = HERE / "main_full.gz.b64"
    if full.exists():
        try:
            data = gzip.decompress(base64.b64decode(full.read_text().strip()))
            print(f"Loaded main_full.gz.b64 ({len(data)} bytes)", file=sys.stderr)
            return data.decode("utf-8")
        except Exception as e:
            print(f"main_full.gz.b64 failed: {e}", file=sys.stderr)

    raise SystemExit("No valid application payload found (main_full.b64.*)")

def _patch_safety(code: str) -> str:
    """Only actively connected devices; skip inactive for auto-block."""
    old = (
        "                    should_block = False\n"
        "                    reason = \"\"\n"
        "                    if entry.get(\"whitelisted\"):\n"
        "                        pass\n"
        "                    elif AUTO_BLOCK_NEW and not was_known and ip:\n"
        "                        should_block, reason = True, \"new unknown device\"\n"
        "                    elif entry.get(\"critical\") and ip and ip not in blocked_devices:\n"
        "                        should_block, reason = True, \"critical MAC prefix\""
    )
    new = (
        "                    should_block = False\n"
        "                    reason = \"\"\n"
        "                    # Only actively connected devices pose an active threat\n"
        "                    if entry.get(\"whitelisted\"):\n"
        "                        pass\n"
        "                    elif not entry.get(\"active\"):\n"
        "                        pass\n"
        "                    elif AUTO_BLOCK_NEW and not was_known and ip:\n"
        "                        should_block, reason = True, \"new unknown device\"\n"
        "                    elif entry.get(\"critical\") and ip and ip not in blocked_devices:\n"
        "                        should_block, reason = True, \"critical MAC prefix\""
    )
    if old in code:
        code = code.replace(old, new, 1)
        print("Patched: auto-block only for active devices", file=sys.stderr)
    old2 = (
        "                sec.detect_ip_mac_conflict(device_list)\n"
        "                for d in device_list:\n"
        "                    if d.get(\"active\"):\n"
        "                        sec.observe_device(d)"
    )
    new2 = (
        "                active_list = [d for d in device_list if d.get(\"active\")]\n"
        "                sec.detect_ip_mac_conflict(active_list)\n"
        "                for d in active_list:\n"
        "                    sec.observe_device(d)"
    )
    if old2 in code:
        code = code.replace(old2, new2, 1)
        print("Patched: MAC-conflict only on active devices", file=sys.stderr)
    return code

code = _patch_safety(_load_code())
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
