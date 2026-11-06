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
    return code


def _patch_features(code: str) -> str:
    if "/api/security/deep-scan" not in code:
        injection = """

@app.route("/api/security/deep-scan", methods=["POST"])
def api_deep_scan():
    try:
        with _lock:
            targets = [d.get("ip") for d in known_devices.values() if d.get("active") and d.get("ip") and not d.get("whitelisted")]
        targets = [t for t in targets if t][:24]
        sec = get_security()
        if not hasattr(sec, "deep_lan_scan"):
            return jsonify({"ok": False, "error": "deep_lan_scan not available"}), 500
        result = sec.deep_lan_scan(targets)
        return jsonify({"ok": True, **result})
    except Exception as exp:
        log.error("deep-scan: %s", exp)
        return jsonify({"ok": False, "error": str(exp)}), 500

@app.route("/api/config/effective")
def api_config_effective():
    return jsonify({
        "fritzbox_host": FRITZBOX_HOST, "network_cidr": NETWORK_CIDR, "scan_interval": SCAN_INTERVAL,
        "auto_block_new": AUTO_BLOCK_NEW, "notify_on_block": NOTIFY_ON_BLOCK,
        "enable_perimeter_scan": ENABLE_PERIMETER, "perimeter_interval": PERIMETER_INTERVAL,
        "enable_threat_intel": ENABLE_THREAT_INTEL, "threat_intel_interval": THREAT_INTEL_INTERVAL,
        "auto_block_threat_intel": AUTO_BLOCK_THREAT_INTEL, "critical_mac_prefixes": CRITICAL_MAC_PREFIXES,
        "deep_scan_on_new": os.getenv("DEEP_SCAN_ON_NEW", "false").lower() in ("true", "1", "yes"),
        "log_alert_notify": os.getenv("LOG_ALERT_NOTIFY", "true").lower() in ("true", "1", "yes"),
        "version": "2.2.8",
    })
"""
        marker = '\nif __name__ == "__main__":'
        code = code.replace(marker, injection + marker, 1) if marker in code else code + injection
        print("Patched: deep-scan + config", file=sys.stderr)

    if "/api/capture/status" not in code:
        cap = """

_packet_cap = None
def get_packet_capture():
    global _packet_cap
    if _packet_cap is None:
        from packet_capture import PacketCapture
        import hashlib, xml.etree.ElementTree as ET
        def _web_sid():
            try:
                import requests as _req
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                except Exception:
                    pass
                base = f"https://{FRITZBOX_HOST}"
                r = _req.get(f"{base}/login_sid.lua", timeout=10, verify=False)
                root = ET.fromstring(r.text)
                challenge = root.findtext("Challenge") or ""
                if not challenge or not FRITZBOX_PASSWORD:
                    return None
                resp = challenge + "-" + hashlib.md5((challenge + "-" + FRITZBOX_PASSWORD).encode("utf-16le")).hexdigest()
                params = {"response": resp}
                if FRITZBOX_USER:
                    params["username"] = FRITZBOX_USER
                r2 = _req.get(f"{base}/login_sid.lua", params=params, timeout=10, verify=False)
                sid = ET.fromstring(r2.text).findtext("SID") or ""
                if sid and sid != "0000000000000000":
                    return sid
            except Exception as exc:
                log.warning("web SID login failed: %s", exc)
            return None
        _packet_cap = PacketCapture(host=FRITZBOX_HOST, password=FRITZBOX_PASSWORD, user=FRITZBOX_USER, get_sid=_web_sid)
    return _packet_cap

@app.route("/api/capture/status")
def api_capture_status():
    return jsonify(get_packet_capture().status())

@app.route("/api/capture/interfaces")
def api_capture_interfaces():
    return jsonify({"interfaces": get_packet_capture().list_interfaces()})

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data = request.get_json(force=True, silent=True) or {}
    iface = (data.get("iface") or data.get("interface") or "1-lan").strip()
    duration = int(data.get("duration_sec") or data.get("duration") or 0)
    snaplen = int(data.get("snaplen") or 0)
    result = get_packet_capture().start(iface=iface, snaplen=snaplen, duration_sec=duration)
    return jsonify(result), (200 if result.get("ok") else 400)

@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    return jsonify(get_packet_capture().stop())

@app.route("/api/capture/list")
def api_capture_list():
    return jsonify({"captures": get_packet_capture().list_captures()})

@app.route("/api/capture/delete", methods=["POST"])
def api_capture_delete():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "message": "name required"}), 400
    return jsonify(get_packet_capture().delete_capture(name))

@app.route("/api/capture/analyze", methods=["POST"])
def api_capture_analyze():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "message": "name required"}), 400
    return jsonify(get_packet_capture().analyze(name, limit=int(data.get("limit") or 50)))

@app.route("/api/capture/download/<path:name>")
def api_capture_download(name: str):
    from flask import send_file
    from pathlib import Path as _P
    safe = _P(name).name
    p = _P(os.getenv("DATA_DIR", "/data")) / "captures" / safe
    if not p.exists() or p.suffix != ".pcap":
        return jsonify({"ok": False, "message": "not found"}), 404
    return send_file(p, as_attachment=True, download_name=p.name, mimetype="application/vnd.tcpdump.pcap")
"""
        marker = '\nif __name__ == "__main__":'
        code = code.replace(marker, cap + marker, 1) if marker in code else code + cap
        print("Patched: packet capture API", file=sys.stderr)

    for a, b in [('"version": "1.5.0"', '"version": "2.2.8"'), ('"version": "2.1.0"', '"version": "2.2.8"'),
                 ("Network Guard 2.1.0", "Network Guard 2.2.8")]:
        code = code.replace(a, b)
    return code


code = _patch_features(_patch_safety(_load_code()))
exec(compile(code, str(HERE / "main_assembled.py"), "exec"), globals())
