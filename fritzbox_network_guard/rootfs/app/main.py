#!/usr/bin/env python3
"""Load application from main_full.b64.* and apply safety + feature patches."""
from __future__ import annotations
import base64
import gzip
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_code() -> str:
    chunks = sorted(HERE.glob("main_full.b64.*"))
    if chunks:
        b64 = "".join(c.read_text().strip() for c in chunks)
        data = gzip.decompress(base64.b64decode(b64))
        print(f"Assembled main_full from {len(chunks)} chunks ({len(data)} bytes)", file=sys.stderr)
        return data.decode("utf-8")
    full = HERE / "main_full.gz.b64"
    if full.exists():
        data = gzip.decompress(base64.b64decode(full.read_text().strip()))
        return data.decode("utf-8")
    raise SystemExit("No valid application payload found (main_full.b64.*)")


def _patch_safety(code: str) -> str:
    if "_insights = None" not in code:
        marker = "_security: SecurityEngine | None = None"
        if marker in code:
            code = code.replace(
                marker,
                marker + "\n_insights = None  # type: ignore",
                1,
            )
            print("Patched: _insights = None init", file=sys.stderr)

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

    # soft block_ip for 714/401 kept from previous patches via string match in full file
    return code


def _patch_features(code: str) -> str:
    # Full FritzBox reset: unblock all WAN + disable MAC filter
    if "/api/reset/fritz" not in code:
        reset_ep = '''
@app.route("/api/reset/fritz", methods=["POST"])
def api_reset_fritz():
    """Remove all Network-Guard changes on the FritzBox: WAN blocks + MAC filter OFF."""
    unblocked = []
    errors = []
    with _lock:
        ips = list(blocked_devices.keys())
    for ip in ips:
        try:
            if unblock_ip(ip):
                unblocked.append(ip)
            else:
                errors.append(f"unblock_failed:{ip}")
        except Exception as exc:
            errors.append(f"unblock_exc:{ip}:{exc}")
    with _lock:
        blocked_devices.clear()
        for d in known_devices.values():
            d["blocked"] = False
        save_json(BLOCKED_FILE, blocked_devices)
        save_json(KNOWN_FILE, known_devices)
    q = apply_mac_quarantine()
    # Force MAC filter off even if apply had issues
    try:
        mq = get_mac_q()
        if mq.set_filter_enabled(False):
            q["filter_enabled"] = False
            scan_stats["mac_filter_active"] = False
            log.info("MAC filter FORCE DISABLED via reset")
        else:
            errors.append("mac_filter_disable_failed")
    except Exception as exc:
        errors.append(f"mac_filter_exc:{exc}")
        log.exception("Reset MAC filter force-off failed")
    msg = f"Reset: {len(unblocked)} IP(s) entsperrt, MAC-Filter {'AUS' if not q.get('filter_enabled') else 'noch AN'}"
    notify_ha("Network Guard – FritzBox Reset", msg)
    return jsonify({
        "ok": True,
        "message": msg,
        "unblocked": unblocked,
        "mac_quarantine": q,
        "errors": errors,
    })
'''
        marker = '\nif __name__ == "__main__":'
        if marker in code:
            code = code.replace(marker, reset_ep + marker, 1)
            print("Patched: /api/reset/fritz endpoint", file=sys.stderr)
        else:
            code = code + reset_ep
            print("Patched: /api/reset/fritz endpoint (append)", file=sys.stderr)

    for a, b in [
        ('"version": "1.5.0"', '"version": "2.4.3"'),
        ('"version": "2.1.0"', '"version": "2.4.3"'),
        ('"version": "2.2.0"', '"version": "2.4.3"'),
        ('"version": "2.2.3"', '"version": "2.4.3"'),
        ('"version": "2.2.9"', '"version": "2.4.3"'),
        ('"version": "2.3.2"', '"version": "2.4.3"'),
        ('"version": "2.3.3"', '"version": "2.4.3"'),
        ('"version": "2.3.4"', '"version": "2.4.3"'),
        ('"version": "2.4.0"', '"version": "2.4.3"'),
        ('"version": "2.4.1"', '"version": "2.4.3"'),
        ('"version": "2.4.2"', '"version": "2.4.3"'),
        ("Network Guard 1.4.0", "Network Guard 2.4.3"),
        ("Network Guard 2.1.0", "Network Guard 2.4.3"),
        ("Network Guard 2.2.0", "Network Guard 2.4.3"),
        ("Network Guard 2.2.9", "Network Guard 2.4.3"),
        ("Network Guard 2.3.2", "Network Guard 2.4.3"),
        ("Network Guard 2.3.3", "Network Guard 2.4.3"),
        ("Network Guard 2.3.4", "Network Guard 2.4.3"),
        ("Network Guard 2.4.0", "Network Guard 2.4.3"),
        ("Network Guard 2.4.1", "Network Guard 2.4.3"),
        ("Network Guard 2.4.2", "Network Guard 2.4.3"),
    ]:
        if a in code:
            code = code.replace(a, b)
    return code


code = _patch_features(_patch_safety(_load_code()))
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
