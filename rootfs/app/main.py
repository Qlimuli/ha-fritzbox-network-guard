#!/usr/bin/env python3
"""FritzBox Network Guard – production WSGI + rich UI + SecurityEngine."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from fritzconnection import FritzConnection
import requests
from mac_guard import MacQuarantine, norm_mac
from security_engine import SecurityEngine

FRITZBOX_HOST = os.getenv("FRITZBOX_HOST", "fritz.box")
FRITZBOX_USER = os.getenv("FRITZBOX_USER", "")
FRITZBOX_PASSWORD = os.getenv("FRITZBOX_PASSWORD", "")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))
NETWORK_CIDR = os.getenv("NETWORK_CIDR", "192.168.178.0/24")
CRITICAL_MAC_PREFIXES = [
    p.strip().upper().replace("-", ":")
    for p in os.getenv("CRITICAL_MAC_PREFIXES", "").split(",")
    if p.strip()
]
AUTO_BLOCK_NEW = os.getenv("AUTO_BLOCK_NEW", "true").lower() in ("true", "1", "yes")
NOTIFY_ON_BLOCK = os.getenv("NOTIFY_ON_BLOCK", "true").lower() in ("true", "1", "yes")
SUPERVISOR_TOKEN = os.getenv("SUPERVISOR_TOKEN", "")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
APP_DIR = Path(__file__).resolve().parent
BLOCKED_FILE = DATA_DIR / "blocked_devices.json"
KNOWN_FILE = DATA_DIR / "known_devices.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("network-guard")


def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
    return default


def save_json(path: Path, data: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        log.error("Could not save %s: %s", path, exc)


blocked_devices: dict[str, dict] = load_json(BLOCKED_FILE, {})
known_devices: dict[str, dict] = load_json(KNOWN_FILE, {})
whitelist: set[str] = set(load_json(WHITELIST_FILE, []))
scan_stats: dict[str, Any] = {
    "last_scan": None,
    "last_count": 0,
    "total_scans": 0,
    "fritz_ok": None,
    "last_error": None,
    "mac_filter_active": False,
}
_lock = threading.Lock()
_fc = None
_mac_q: MacQuarantine | None = None
_security: SecurityEngine | None = None


def get_fritz():
    global _fc
    if _fc is None:
        log.info("Connecting to FritzBox at %s …", FRITZBOX_HOST)
        _fc = FritzConnection(
            address=FRITZBOX_HOST,
            user=FRITZBOX_USER or None,
            password=FRITZBOX_PASSWORD,
            timeout=15,
        )
        log.info("Connected: %s", _fc)
    return _fc


def block_ip(ip: str, reason: str = "security alert") -> bool:
    try:
        get_fritz().call_action(
            "X_AVM-DE_HostFilter1",
            "DisallowWANAccessByIP",
            arguments={"NewIPv4Address": ip, "NewDisallow": True},
        )
        log.info("Blocked WAN for %s (%s)", ip, reason)
        return True
    except Exception as exc:
        log.error("Block %s failed: %s", ip, exc)
        return False


def unblock_ip(ip: str) -> bool:
    try:
        get_fritz().call_action(
            "X_AVM-DE_HostFilter1",
            "DisallowWANAccessByIP",
            arguments={"NewIPv4Address": ip, "NewDisallow": False},
        )
        log.info("Unblocked WAN for %s", ip)
        return True
    except Exception as exc:
        log.error("Unblock %s failed: %s", ip, exc)
        return False


def notify_ha(title: str, message: str) -> None:
    if not SUPERVISOR_TOKEN or not NOTIFY_ON_BLOCK:
        return
    try:
        requests.post(
            "http://supervisor/core/api/services/persistent_notification/create",
            headers={
                "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "title": title,
                "message": message,
                "notification_id": f"network_guard_{int(time.time())}",
            },
            timeout=5,
        )
    except Exception as exp:
        log.warning("HA notify failed: %s", exp)


def get_security() -> SecurityEngine:
    global _security
    if _security is None:
        _security = SecurityEngine(
            DATA_DIR,
            block_ip_fn=block_ip,
            notify_fn=notify_ha,
            auto_block=True,
            perimeter_interval=int(os.getenv("PERIMETER_INTERVAL", "3600")),
            threat_intel_interval=int(os.getenv("THREAT_INTEL_INTERVAL", "21600")),
        )
    return _security


def get_mac_q() -> MacQuarantine:
    global _mac_q
    if _mac_q is None:
        _mac_q = MacQuarantine(
            FRITZBOX_HOST,
            FRITZBOX_USER,
            FRITZBOX_PASSWORD,
            get_fritz,
            scan_stats,
        )
    return _mac_q


def apply_mac_quarantine() -> dict:
    with _lock:
        blocked = dict(blocked_devices)
        known = dict(known_devices)
    return get_mac_q().apply(blocked, known)


def fetch_fritz_hosts() -> list:
    hosts = []
    try:
        fc = get_fritz()
        try:
            n = int(fc.call_action("Hosts1", "GetHostNumberOfEntries").get("NewHostNumberOfEntries", 0))
        except Exception:
            n = 0
        for i in range(n):
            try:
                h = fc.call_action("Hosts1", "GetGenericHostEntry", NewIndex=i)
                mac = (h.get("NewMACAddress") or "").upper()
                ip = h.get("NewIPAddress") or ""
                if not ip and not mac:
                    continue
                hosts.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": h.get("NewHostName") or "",
                    "active": bool(h.get("NewActive", False)),
                    "interface": h.get("NewInterfaceType") or "",
                    "address_source": h.get("NewAddressSource") or "",
                    "lease": h.get("NewLeaseTimeRemaining"),
                })
            except Exception:
                continue
        scan_stats["fritz_ok"] = True
    except Exception as exc:
        log.warning("Fritz host list failed: %s", exc)
        scan_stats["fritz_ok"] = False
        scan_stats["last_error"] = str(exc)
    return hosts


def scan_nmap() -> list:
    devices = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", "--max-retries", "1", "--host-timeout", "3s", NETWORK_CIDR],
            capture_output=True, text=True, timeout=120,
        )
        current: dict = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                if current.get("ip"):
                    devices.append(current)
                parts = line.split()
                ip = parts[-1].strip("()")
                hostname = parts[4] if len(parts) > 5 else ""
                current = {"ip": ip, "hostname": hostname, "mac": "", "vendor": ""}
            elif "MAC Address:" in line:
                mac_part = line.split("MAC Address:")[1].strip()
                current["mac"] = mac_part.split()[0].upper()
                current["vendor"] = " ".join(mac_part.split()[1:]).strip("()")
        if current.get("ip"):
            devices.append(current)
    except Exception as exp:
        log.warning("nmap failed: %s", exp)
        scan_stats["last_error"] = str(exp)
    return devices


def is_critical(mac: str) -> bool:
    mac = (mac or "").upper()
    return any(mac.startswith(p) for p in CRITICAL_MAC_PREFIXES) if mac else False


def is_whitelisted(ip: str, mac: str) -> bool:
    return ip in whitelist or (mac and mac.upper() in whitelist)


def merge_device(base: dict, extra: dict) -> dict:
    out = dict(base)
    for k, v in extra.items():
        if v is not None and v != "":
            out[k] = v
    return out


def scanner_loop() -> None:
    log.info("Scanner started – interval %ss, network %s", SCAN_INTERVAL, NETWORK_CIDR)
    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()
            nmap_devs = scan_nmap()
            fritz_devs = fetch_fritz_hosts()
            by_ip: dict = {}
            by_mac: dict = {}
            for d in nmap_devs:
                ip = d.get("ip") or ""
                mac = (d.get("mac") or "").upper()
                entry = {
                    "ip": ip, "mac": mac, "hostname": d.get("hostname") or "",
                    "vendor": d.get("vendor") or "", "source": "nmap",
                    "active": True, "last_seen": now,
                }
                if ip:
                    by_ip[ip] = entry
                if mac:
                    by_mac[mac] = entry
            for d in fritz_devs:
                ip = d.get("ip") or ""
                mac = (d.get("mac") or "").upper()
                existing = by_ip.get(ip) or by_mac.get(mac) or {}
                entry = merge_device(existing, {
                    "ip": ip or existing.get("ip"),
                    "mac": mac or existing.get("mac"),
                    "hostname": d.get("hostname") or existing.get("hostname"),
                    "vendor": existing.get("vendor"),
                    "active": d.get("active"),
                    "interface": d.get("interface"),
                    "address_source": d.get("address_source"),
                    "lease": d.get("lease"),
                    "source": "fritz+nmap" if existing else "fritz",
                    "last_seen": now if d.get("active") else existing.get("last_seen", now),
                })
                if ip:
                    by_ip[ip] = entry
                if mac:
                    by_mac[mac] = entry
            seen: set = set()
            need_q = False
            with _lock:
                for entry in list(by_ip.values()) + list(by_mac.values()):
                    ip = entry.get("ip") or ""
                    mac = (entry.get("mac") or "").upper()
                    key = mac or ip
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    prev = known_devices.get(key, {})
                    entry["first_seen"] = prev.get("first_seen", now)
                    entry["critical"] = is_critical(mac)
                    entry["whitelisted"] = is_whitelisted(ip, mac)
                    entry["blocked"] = ip in blocked_devices
                    was_known = bool(prev.get("first_seen"))
                    known_devices[key] = entry
                    should_block = False
                    reason = ""
                    if entry.get("whitelisted"):
                        pass
                    elif AUTO_BLOCK_NEW and not was_known and ip:
                        should_block, reason = True, "new unknown device"
                    elif entry.get("critical") and ip and ip not in blocked_devices:
                        should_block, reason = True, "critical MAC prefix"
                    if should_block and ip and ip not in blocked_devices:
                        if block_ip(ip, reason):
                            blocked_devices[ip] = {
                                "ip": ip, "mac": mac,
                                "hostname": entry.get("hostname", ""),
                                "vendor": entry.get("vendor", ""),
                                "reason": reason, "blocked_at": now,
                            }
                            entry["blocked"] = True
                            notify_ha("Network Guard – Device blocked", f"IP {ip} ({mac or 'no MAC'}) – {reason}")
                            entry["_need_mac_quarantine"] = True
                need_q = any(d.pop("_need_mac_quarantine", False) for d in known_devices.values())
                save_json(KNOWN_FILE, known_devices)
                save_json(BLOCKED_FILE, blocked_devices)
                scan_stats["last_scan"] = now
                scan_stats["last_count"] = len(seen)
                scan_stats["total_scans"] = scan_stats.get("total_scans", 0) + 1
            if need_q:
                try:
                    apply_mac_quarantine()
                except Exception as qe:
                    log.exception("MAC quarantine after auto-block: %s", qe)
            try:
                sec = get_security()
                with _lock:
                    device_list = list(known_devices.values())
                sec.detect_ip_mac_conflict(device_list)
                for d in device_list:
                    if d.get("active"):
                        sec.observe_device(d)
            except Exception as se:
                log.warning("security engine lan hooks: %s", se)
            log.info("Scan found %d devices (nmap=%d fritz=%d)", len(seen), len(nmap_devs), len(fritz_devs))
        except Exception as exp:
            log.exception("Scanner error: %s", exp)
            scan_stats["last_error"] = str(exp)
        time.sleep(SCAN_INTERVAL)


app = Flask(__name__)


@app.route("/")
def index():
    return send_from_directory(APP_DIR, "ui.html")


@app.route("/api/status")
def api_status():
    with _lock:
        return jsonify({
            "fritzbox_host": FRITZBOX_HOST,
            "fritzbox_user_set": bool(FRITZBOX_USER),
            "network_cidr": NETWORK_CIDR,
            "scan_interval": SCAN_INTERVAL,
            "auto_block_new": AUTO_BLOCK_NEW,
            "notify_on_block": NOTIFY_ON_BLOCK,
            "critical_mac_prefixes": CRITICAL_MAC_PREFIXES,
            "whitelist_count": len(whitelist),
            "mac_filter_active": scan_stats.get("mac_filter_active", False),
            **scan_stats,
        })


@app.route("/api/known")
def api_known():
    with _lock:
        return jsonify({"devices": known_devices, "count": len(known_devices)})


@app.route("/api/blocked")
def api_blocked():
    with _lock:
        return jsonify({"devices": blocked_devices, "count": len(blocked_devices), "scan_interval": SCAN_INTERVAL})


@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = data.get("reason") or "manual"
    if not ip:
        return jsonify({"ok": False, "message": "IP fehlt"}), 400
    mac = hostname = vendor = ""
    with _lock:
        for d in known_devices.values():
            if d.get("ip") == ip:
                mac = (d.get("mac") or "").upper()
                hostname = d.get("hostname") or ""
                vendor = d.get("vendor") or ""
                break
    if block_ip(ip, reason):
        with _lock:
            blocked_devices[ip] = {"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor, "reason": reason, "blocked_at": datetime.now(timezone.utc).isoformat()}
            for d in known_devices.values():
                if d.get("ip") == ip:
                    d["blocked"] = True
            save_json(BLOCKED_FILE, blocked_devices)
            save_json(KNOWN_FILE, known_devices)
        q = apply_mac_quarantine()
        notify_ha("Network Guard – Device blocked", f"IP {ip} manuell gesperrt (WAN + MAC-Filter)")
        return jsonify({"ok": True, "message": f"{ip} gesperrt (WAN + MAC-Quarantäne)", "mac_quarantine": q})
    return jsonify({"ok": False, "message": "FritzBox-Befehl fehlgeschlagen"}), 500


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "message": "IP fehlt"}), 400
    if unblock_ip(ip):
        with _lock:
            blocked_devices.pop(ip, None)
            for d in known_devices.values():
                if d.get("ip") == ip:
                    d["blocked"] = False
            save_json(BLOCKED_FILE, blocked_devices)
            save_json(KNOWN_FILE, known_devices)
        q = apply_mac_quarantine()
        return jsonify({"ok": True, "message": f"{ip} entsperrt" + (" – MAC-Filter aus" if not q.get("filter_enabled") else ""), "mac_quarantine": q})
    return jsonify({"ok": False, "message": "FritzBox-Befehl fehlgeschlagen"}), 500


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist():
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    mac = (data.get("mac") or "").strip().upper()
    key = ip or mac
    if not key:
        return jsonify({"ok": False, "message": "IP/MAC fehlt"}), 400
    with _lock:
        if key in whitelist or (mac and mac in whitelist) or (ip and ip in whitelist):
            whitelist.discard(ip)
            whitelist.discard(mac)
            msg = f"{key} von Whitelist entfernt"
        else:
            if ip:
                whitelist.add(ip)
            if mac:
                whitelist.add(mac)
            msg = f"{key} zur Whitelist hinzugefügt"
        save_json(WHITELIST_FILE, sorted(whitelist))
        for d in known_devices.values():
            d["whitelisted"] = is_whitelisted(d.get("ip") or "", d.get("mac") or "")
        save_json(KNOWN_FILE, known_devices)
    return jsonify({"ok": True, "message": msg})


@app.route("/api/security")
def api_security():
    return jsonify(get_security().status())


@app.route("/api/security/events")
def api_security_events():
    limit = int(request.args.get("limit", 100))
    return jsonify({"events": get_security().list_events(limit)})


@app.route("/api/security/perimeter", methods=["POST"])
def api_security_perimeter():
    return jsonify(get_security().scan_perimeter())


@app.route("/api/security/threat-intel", methods=["POST"])
def api_security_threat_intel():
    return jsonify(get_security().refresh_threat_intel())


@app.route("/api/security/check-ip", methods=["POST"])
def api_security_check_ip():
    data = request.get_json(force=True, silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "message": "IP fehlt"}), 400
    hit = get_security().ip_in_threat_intel(ip)
    return jsonify({"ip": ip, "listed": bool(hit), "match": hit})


@app.route("/api/security/webhook", methods=["POST"])
def api_security_webhook():
    data = request.get_json(force=True, silent=True) or {}
    if not data:
        return jsonify({"ok": False, "message": "empty payload"}), 400
    if "alert" in data and isinstance(data["alert"], dict):
        data = {**data, "signature": data["alert"].get("signature"), "severity": data["alert"].get("severity"), "src_ip": data.get("src_ip"), "dest_ip": data.get("dest_ip"), "sensor": "suricata"}
    evt = get_security().ingest_external_alert(data)
    return jsonify({"ok": True, "event": evt})


if __name__ == "__main__":
    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()
    try:
        get_security().start_background()
    except Exception as exp:
        log.error("SecurityEngine start failed: %s", exp)
    from waitress import serve
    log.info("Web UI (waitress) on 0.0.0.0:8099")
    serve(app, host="0.0.0.0", port=8099, threads=4, ident="NetworkGuard")
