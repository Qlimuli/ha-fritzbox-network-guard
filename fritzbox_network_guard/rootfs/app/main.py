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


def _patch_features(code: str) -> str:
    """Inject deep-scan API and richer nmap if not present."""
    if "/api/security/deep-scan" in code:
        return code
    injection = '''

@app.route("/api/security/deep-scan", methods=["POST"])
def api_deep_scan():
    """Detailed service scan of currently active LAN hosts (no auto-block)."""
    try:
        with _lock:
            targets = [
                d.get("ip") for d in known_devices.values()
                if d.get("active") and d.get("ip") and not d.get("whitelisted")
            ]
        targets = [t for t in targets if t][:24]
        sec = get_security()
        if not hasattr(sec, "deep_lan_scan"):
            return jsonify({"ok": False, "error": "deep_lan_scan not available in SecurityEngine"}), 500
        result = sec.deep_lan_scan(targets)
        return jsonify({"ok": True, **result})
    except Exception as exp:
        log.error("deep-scan: %s", exp)
        return jsonify({"ok": False, "error": str(exp)}), 500


@app.route("/api/config/effective")
def api_config_effective():
    """Expose effective runtime config for the Einstellungen tab (no secrets)."""
    return jsonify({
        "fritzbox_host": FRITZBOX_HOST,
        "network_cidr": NETWORK_CIDR,
        "scan_interval": SCAN_INTERVAL,
        "auto_block_new": AUTO_BLOCK_NEW,
        "notify_on_block": NOTIFY_ON_BLOCK,
        "enable_perimeter_scan": ENABLE_PERIMETER,
        "perimeter_interval": PERIMETER_INTERVAL,
        "enable_threat_intel": ENABLE_THREAT_INTEL,
        "threat_intel_interval": THREAT_INTEL_INTERVAL,
        "auto_block_threat_intel": AUTO_BLOCK_THREAT_INTEL,
        "critical_mac_prefixes": CRITICAL_MAC_PREFIXES,
        "deep_scan_on_new": os.getenv("DEEP_SCAN_ON_NEW", "false").lower() in ("true", "1", "yes"),
        "log_alert_notify": os.getenv("LOG_ALERT_NOTIFY", "true").lower() in ("true", "1", "yes"),
        "version": "2.1.0",
    })

'''
    marker = '\nif __name__ == "__main__":'
    if marker in code:
        code = code.replace(marker, injection + marker, 1)
        print("Patched: deep-scan + config/effective API", file=sys.stderr)
    else:
        code = code + injection
        print("Patched: appended deep-scan API", file=sys.stderr)
    code = code.replace('"version": "1.5.0"', '"version": "2.1.0"')
    code = code.replace('"version": "1.4.0"', '"version": "2.1.0"')
    code = code.replace("Network Guard 1.4.0", "Network Guard 2.1.0")
    return code


code = _patch_features(_patch_safety(_load_code()))
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
