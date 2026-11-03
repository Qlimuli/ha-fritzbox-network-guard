#!/usr/bin/env python3
"""
FritzBox Network Guard – Home Assistant Add-on

Features:
- Periodic network scan (nmap / ARP)
- Detects new / critical devices
- On alert: blocks IP via FritzBox X_AVM-DE_HostFilter (DisallowWANAccessByIP)
- Web UI to list blocked devices and unblock them
- Optional Home Assistant notifications
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from fritzconnection import FritzConnection
from fritzconnection.core.exceptions import FritzConnectionException, FritzServiceError
import requests

# ---------------------------------------------------------------------------
# Config from environment (set by run.sh)
# ---------------------------------------------------------------------------
FRITZBOX_HOST = os.getenv("FRITZBOX_HOST", "fritz.box")
FRITZBOX_USER = os.getenv("FRITZBOX_USER", "")
FRITZBOX_PASSWORD = os.getenv("FRITZBOX_PASSWORD", "")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))
NETWORK_CIDR = os.getenv("NETWORK_CIDR", "192.168.178.0/24")
CRITICAL_MAC_PREFIXES = [
    p.strip().upper() for p in os.getenv("CRITICAL_MAC_PREFIXES", "").split(",") if p.strip()
]
AUTO_BLOCK_NEW = os.getenv("AUTO_BLOCK_NEW", "true").lower() in ("true", "1", "yes")
NOTIFY_ON_BLOCK = os.getenv("NOTIFY_ON_BLOCK", "true").lower() in ("true", "1", "yes")
SUPERVISOR_TOKEN = os.getenv("SUPERVISOR_TOKEN", "")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
BLOCKED_FILE = DATA_DIR / "blocked_devices.json"
KNOWN_FILE = DATA_DIR / "known_devices.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("network-guard")

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
    return default


def save_json(path: Path, data: Any) -> None:
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        log.error("Could not save %s: %s", path, exc)


# In-memory state (synced to disk)
blocked_devices: dict[str, dict] = load_json(BLOCKED_FILE, {})
known_devices: dict[str, dict] = load_json(KNOWN_FILE, {})

# ---------------------------------------------------------------------------
# FritzBox interaction
# ---------------------------------------------------------------------------
_fc: FritzConnection | None = None


def get_fritz() -> FritzConnection:
    global _fc
    if _fc is None:
        log.info("Connecting to FritzBox at %s …", FRITZBOX_HOST)
        _fc = FritzConnection(
            address=FRITZBOX_HOST,
            user=FRITZBOX_USER or None,
            password=FRITZBOX_PASSWORD,
            timeout=10,
        )
        log.info("Connected: %s", _fc)
    return _fc


def block_ip(ip: str, reason: str = "security alert") -> bool:
    """Block WAN access for the given IPv4 address via HostFilter service."""
    try:
        fc = get_fritz()
        fc.call_action(
            "X_AVM-DE_HostFilter1",
            "DisallowWANAccessByIP",
            arguments={
                "NewIPv4Address": ip,
                "NewDisallow": True,
            },
        )
        log.info("Blocked WAN access for %s (%s)", ip, reason)
        return True
    except (FritzConnectionException, FritzServiceError, Exception) as exc:
        log.error("Failed to block %s: %s", ip, exc)
        return False


def unblock_ip(ip: str) -> bool:
    """Re-allow WAN access for the given IPv4 address."""
    try:
        fc = get_fritz()
        fc.call_action(
            "X_AVM-DE_HostFilter1",
            "DisallowWANAccessByIP",
            arguments={
                "NewIPv4Address": ip,
                "NewDisallow": False,
            },
        )
        log.info("Unblocked WAN access for %s", ip)
        return True
    except (FritzConnectionException, FritzServiceError, Exception) as exp:
        log.error("Failed to unblock %s: %s", ip, exp)
        return False


def get_wan_access(ip: str) -> bool | None:
    """Return True if WAN is allowed, False if blocked, None on error."""
    try:
        fc = get_fritz()
        result = fc.call_action(
            "X_AVM-DE_HostFilter1",
            "GetWANAccessByIP",
            arguments={"NewIPv4Address": ip},
        )
        # NewDisallow is True when blocked
        return not result.get("NewDisallow", False)
    except Exception as exp:
        log.debug("GetWANAccessByIP failed for %s: %s", ip, exp)
        return None


# ---------------------------------------------------------------------------
# Network scanning
# ---------------------------------------------------------------------------
def scan_network() -> list[dict]:
    """Simple ARP/nmap based scan of the configured CIDR."""
    devices: list[dict] = []
    try:
        # Prefer nmap if available
        cmd = [
            "nmap",
            "-sn",
            "-n",
            "--max-retries", "1",
            "--host-timeout", "3s",
            NETWORK_CIDR,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        output = result.stdout

        current: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                if current.get("ip"):
                    devices.append(current)
                current = {"ip": line.split()[-1].strip("()"), "hostname": "", "mac": "", "vendor": ""}
                # hostname if present
                parts = line.split()
                if len(parts) > 5:
                    current["hostname"] = parts[4]
            elif "MAC Address:" in line:
                # MAC Address: AA:BB:CC:DD:EE:FF (Vendor)
                mac_part = line.split("MAC Address:")[1].strip()
                mac = mac_part.split()[0].upper()
                vendor = " ".join(mac_part.split()[1:]).strip("()")
                current["mac"] = mac
                current["vendor"] = vendor
        if current.get("ip"):
            devices.append(current)

    except Exception as exp:
        log.warning("nmap scan failed (%s) – falling back to limited ARP", exp)
        # Fallback: just try to resolve a few hosts or keep previous
        pass

    return devices


def is_critical(device: dict) -> bool:
    """Heuristic: new device or matching critical MAC prefix."""
    mac = (device.get("mac") or "").upper()
    if not mac:
        return False
    for prefix in CRITICAL_MAC_PREFIXES:
        if mac.startswith(prefix):
            return True
    return False


def notify_ha(title: str, message: str) -> None:
    """Send a persistent notification via Home Assistant Core API."""
    if not SUPERVISOR_TOKEN or not NOTIFY_ON_BLOCK:
        return
    try:
        url = "http://supervisor/core/api/services/persistent_notification/create"
        headers = {
            "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
            "Content-Type": "application/json",
        }
        payload = {
            "title": title,
            "message": message,
            "notification_id": f"network_guard_{int(time.time())}",
        }
        requests.post(url, headers=headers, json=payload, timeout=5)
    except Exception as exp:
        log.warning("HA notification failed: %s", exp)


# ---------------------------------------------------------------------------
# Main scanner loop
# ---------------------------------------------------------------------------
def scanner_loop() -> None:
    log.info("Scanner started – interval %ss, network %s", SCAN_INTERVAL, NETWORK_CIDR)
    while True:
        try:
            devices = scan_network()
            log.info("Scan found %d devices", len(devices))
            now = datetime.now(timezone.utc).isoformat()

            for dev in devices:
                ip = dev.get("ip")
                mac = (dev.get("mac") or "").upper()
                if not ip:
                    continue

                key = mac or ip
                is_new = key not in known_devices

                # Update known devices
                known_devices[key] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": dev.get("hostname", ""),
                    "vendor": dev.get("vendor", ""),
                    "last_seen": now,
                    "first_seen": known_devices.get(key, {}).get("first_seen", now),
                }

                # Decision to block
                should_block = False
                reason = ""

                if is_new and AUTO_BLOCK_NEW:
                    should_block = True
                    reason = "new unknown device"
                elif is_critical(dev):
                    should_block = True
                    reason = "critical MAC prefix match"

                if should_block and ip not in blocked_devices:
                    if block_ip(ip, reason):
                        blocked_devices[ip] = {
                            "ip": ip,
                            "mac": mac,
                            "hostname": dev.get("hostname", ""),
                            "vendor": dev.get("vendor", ""),
                            "reason": reason,
                            "blocked_at": now,
                        }
                        save_json(BLOCKED_FILE, blocked_devices)
                        notify_ha(
                            "Network Guard – Device blocked",
                            f"IP {ip} ({mac or 'no MAC'}) blocked: {reason}",
                        )

            save_json(KNOWN_FILE, known_devices)

        except Exception as exp:
            log.exception("Scanner iteration error: %s", exp)

        time.sleep(SCAN_INTERVAL)


# ---------------------------------------------------------------------------
# Flask Web UI
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FritzBox Network Guard</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --accent: #38bdf8;
      --danger: #f87171;
      --ok: #4ade80;
      --text: #e2e8f0;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 1.5rem;
    }
    h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
    .subtitle { color: var(--muted); margin-bottom: 1.5rem; }
    .grid { display: grid; gap: 1rem; }
    .card {
      background: var(--card);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid #334155;
    }
    .card h2 { font-size: 1.1rem; margin-bottom: 0.75rem; color: var(--accent); }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 0.5rem 0.4rem; border-bottom: 1px solid #334155; }
    th { color: var(--muted); font-weight: 500; }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-danger { background: #7f1d1d; color: var(--danger); }
    .badge-ok { background: #14532d; color: var(--ok); }
    button {
      background: var(--accent);
      color: #0f172a;
      border: none;
      padding: 0.4rem 0.9rem;
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.85rem;
    }
    button:hover { filter: brightness(1.1); }
    button.danger { background: var(--danger); color: #450a0a; }
    .actions { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 1rem; }
    .status { font-size: 0.85rem; color: var(--muted); margin-top: 1rem; }
    input[type="text"] {
      background: #0f172a;
      border: 1px solid #475569;
      color: var(--text);
      padding: 0.45rem 0.7rem;
      border-radius: 8px;
      width: 180px;
    }
  </style>
</head>
<body>
  <h1>🛡️ FritzBox Network Guard</h1>
  <p class="subtitle">Netzwerk-Scan · FritzBox Blacklist · Isolation</p>

  <div class="grid">
    <div class="card">
      <h2>Gesperrte Geräte (WAN-Zugriff blockiert)</h2>
      <div id="blocked-table">Lade…</div>
      <div class="actions">
        <input type="text" id="manual-ip" placeholder="IP manuell sperren">
        <button onclick="blockManual()">Sperren</button>
        <button onclick="refresh()">Aktualisieren</button>
      </div>
    </div>

    <div class="card">
      <h2>Bekannte Geräte (letzter Scan)</h2>
      <div id="known-table">Lade…</div>
    </div>
  </div>

  <p class="status" id="status"></p>

  <script>
    async function api(path, method = 'GET', body = null) {
      const opts = { method, headers: { 'Content-Type': 'application/json' } };
      if (body) opts.body = JSON.stringify(body);
      const r = await fetch(path, opts);
      return r.json();
    }

    function renderBlocked(data) {
      const devices = data.devices || {};
      const keys = Object.keys(devices);
      if (!keys.length) {
        document.getElementById('blocked-table').innerHTML = '<p style="color:var(--muted)">Keine gesperrten Geräte.</p>';
        return;
      }
      let html = '<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Grund</th><th>Seit</th><th></th></tr></thead><tbody>';
      for (const ip of keys) {
        const d = devices[ip];
        html += `<tr>
          <td>${d.ip}</td>
          <td>${d.mac || '–'}</td>
          <td>${d.hostname || '–'}</td>
          <td><span class="badge badge-danger">${d.reason || '–'}</span></td>
          <td>${(d.blocked_at || '').replace('T', ' ').slice(0, 19)}</td>
          <td><button onclick="unblock('${d.ip}')">Entsperren</button></td>
        </tr>`;
      }
      html += '</tbody></table>';
      document.getElementById('blocked-table').innerHTML = html;
    }

    function renderKnown(data) {
      const devices = data.devices || {};
      const keys = Object.keys(devices).sort();
      if (!keys.length) {
        document.getElementById('known-table').innerHTML = '<p style="color:var(--muted)">Noch keine Geräte gescannt.</p>';
        return;
      }
      let html = '<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname / Vendor</th><th>Zuletzt gesehen</th></tr></thead><tbody>';
      for (const k of keys.slice(0, 50)) {
        const d = devices[k];
        html += `<tr>
          <td>${d.ip}</td>
          <td>${d.mac || '–'}</td>
          <td>${d.hostname || d.vendor || '–'}</td>
          <td>${(d.last_seen || '').replace('T', ' ').slice(0, 19)}</td>
        </tr>`;
      }
      html += '</tbody></table>';
      if (keys.length > 50) html += `<p style="color:var(--muted);margin-top:0.5rem">… und ${keys.length - 50} weitere</p>`;
      document.getElementById('known-table').innerHTML = html;
    }

    async function refresh() {
      const [blocked, known] = await Promise.all([
        api('/api/blocked'),
        api('/api/known'),
      ]);
      renderBlocked(blocked);
      renderKnown(known);
      document.getElementById('status').textContent =
        `Letzte Aktualisierung: ${new Date().toLocaleString()} · Scan-Intervall: ${blocked.scan_interval || '?'}s`;
    }

    async function unblock(ip) {
      if (!confirm(`IP ${ip} wirklich entsperren?`)) return;
      const res = await api('/api/unblock', 'POST', { ip });
      alert(res.message || (res.ok ? 'Entsperrt' : 'Fehler'));
      refresh();
    }

    async function blockManual() {
      const ip = document.getElementById('manual-ip').value.trim();
      if (!ip) return;
      const res = await api('/api/block', 'POST', { ip, reason: 'manual' });
      alert(res.message || (res.ok ? 'Gesperrt' : 'Fehler'));
      document.getElementById('manual-ip').value = '';
      refresh();
    }

    refresh();
    setInterval(refresh, 15000);
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/blocked")
def api_blocked():
    return jsonify({
        "devices": blocked_devices,
        "scan_interval": SCAN_INTERVAL,
        "count": len(blocked_devices),
    })


@app.route("/api/known")
def api_known():
    return jsonify({
        "devices": known_devices,
        "count": len(known_devices),
    })


@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "manual")
    if not ip:
        return jsonify({"ok": False, "message": "IP fehlt"}), 400
    if block_ip(ip, reason):
        blocked_devices[ip] = {
            "ip": ip,
            "mac": "",
            "hostname": "",
            "vendor": "",
            "reason": reason,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(BLOCKED_FILE, blocked_devices)
        notify_ha("Network Guard – Device blocked", f"IP {ip} manuell gesperrt")
        return jsonify({"ok": True, "message": f"{ip} gesperrt"})
    return jsonify({"ok": False, "message": "FritzBox-Befehl fehlgeschlagen"}), 500


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False, "message": "IP fehlt"}), 400
    if unblock_ip(ip):
        blocked_devices.pop(ip, None)
        save_json(BLOCKED_FILE, blocked_devices)
        return jsonify({"ok": True, "message": f"{ip} entsperrt"})
    return jsonify({"ok": False, "message": "FritzBox-Befehl fehlgeschlagen"}), 500


@app.route("/api/status")
def api_status():
    return jsonify({
        "fritzbox_host": FRITZBOX_HOST,
        "network_cidr": NETWORK_CIDR,
        "scan_interval": SCAN_INTERVAL,
        "auto_block_new": AUTO_BLOCK_NEW,
        "blocked_count": len(blocked_devices),
        "known_count": len(known_devices),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Start background scanner
    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()

    # Web server (Ingress listens on 8099)
    log.info("Web UI listening on 0.0.0.0:8099")
    app.run(host="0.0.0.0", port=8099, debug=False, use_reloader=False)
