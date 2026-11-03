#!/usr/bin/env python3
"""
Intelligent threat defense for FritzBox Network Guard.

In-addon capabilities (realistic on HA host_network):
  1. Perimeter: scan public WAN IP for unexpected open ports
  2. Threat intelligence: refresh public blocklists, match local peers
  3. LAN asset anomalies: new devices, MAC conflicts (spoof heuristic)
  4. Event bus + auto-response (FritzBox WAN block + HA notify)
  5. Ingress webhooks for external NIDS/HIDS (Suricata, Wazuh, Zeek)

NOT in-addon (documented integration only – need dedicated sensors):
  - Full DPI / Suricata inline
  - True DDoS volumetric mitigation
  - Rogue AP detection (needs monitor-mode WiFi)
  - Host FIM / process monitoring (Wazuh agent on each host)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import requests

log = logging.getLogger("security-engine")

RISKY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

BLOCKLIST_FEEDS = [
    {"name": "firehol_level1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "severity": "high"},
    {"name": "spamhaus_drop", "url": "https://www.spamhaus.org/drop/drop.txt", "severity": "critical"},
    {"name": "spamhaus_edrop", "url": "https://www.spamhaus.org/drop/edrop.txt", "severity": "critical"},
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


class SecurityEngine:
    def __init__(self, data_dir: Path, *, block_ip_fn: Callable[[str, str], bool], notify_fn: Callable[[str, str], None], auto_block: bool = True, perimeter_interval: int = 3600, threat_intel_interval: int = 21600, risky_ports: list[int] | None = None):
        self.data_dir = Path(data_dir)
        self.block_ip_fn = block_ip_fn
        self.notify_fn = notify_fn
        self.auto_block = auto_block
        self.perimeter_interval = max(300, int(perimeter_interval))
        self.threat_intel_interval = max(3600, int(threat_intel_interval))
        self.risky_ports = risky_ports or list(RISKY_PORTS.keys())
        self.events_file = self.data_dir / "security_events.json"
        self.intel_file = self.data_dir / "threat_intel.json"
        self.perimeter_file = self.data_dir / "perimeter_scan.json"
        self.mac_history_file = self.data_dir / "mac_ip_history.json"
        self.events: list[dict] = self._load(self.events_file, [])
        self.intel: dict[str, Any] = self._load(self.intel_file, {"networks": [], "updated": None, "sources": []})
        self.perimeter: dict[str, Any] = self._load(self.perimeter_file, {})
        self.mac_history: dict[str, list] = self._load(self.mac_history_file, {})
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.stats = {"perimeter_last": None, "perimeter_open_ports": [], "threat_intel_count": 0, "threat_intel_updated": None, "events_total": len(self.events), "last_alert": None, "public_ip": None}

    def _load(self, path: Path, default: Any) -> Any:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("load %s: %s", path, exc)
        return default

    def _save(self, path: Path, data: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            log.error("save %s: %s", path, exc)

    def raise_event(self, category: str, severity: str, title: str, detail: str, *, ip: str | None = None, mac: str | None = None, source: str = "engine", auto_block: bool | None = None, meta: dict | None = None) -> dict:
        evt = {"id": f"{int(time.time()*1000)}_{category}", "ts": _now(), "category": category, "severity": severity, "title": title, "detail": detail, "ip": ip, "mac": mac, "source": source, "meta": meta or {}, "blocked": False}
        do_block = self.auto_block if auto_block is None else auto_block
        if do_block and ip and severity in ("high", "critical"):
            try:
                if self.block_ip_fn(ip, f"{category}: {title}"):
                    evt["blocked"] = True
            except Exception as exp:
                log.error("auto-block %s failed: %s", ip, exp)
        with self._lock:
            self.events.insert(0, evt)
            self.events = self.events[:500]
            self.stats["events_total"] = len(self.events)
            self.stats["last_alert"] = evt["ts"]
            self._save(self.events_file, self.events)
        try:
            self.notify_fn(f"[{severity.upper()}] {title}", detail)
        except Exception:
            pass
        log.warning("SECURITY %s/%s: %s – %s", severity, category, title, detail)
        return evt

    def list_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(self.events[:limit])

    def resolve_public_ip(self) -> str | None:
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                r = requests.get(url, timeout=8)
                if r.ok:
                    ip = r.text.strip()
                    ipaddress.ip_address(ip)
                    self.stats["public_ip"] = ip
                    return ip
            except Exception:
                continue
        return None

    def scan_perimeter(self) -> dict:
        public_ip = self.resolve_public_ip()
        result = {"ts": _now(), "public_ip": public_ip, "open_ports": [], "error": None}
        if not public_ip:
            result["error"] = "public IP unknown"
            self.perimeter = result
            self._save(self.perimeter_file, result)
            return result
        ports = ",".join(str(p) for p in sorted(self.risky_ports))
        try:
            cmd = ["nmap", "-Pn", "-n", "--open", "-p", ports, "--max-retries", "1", "--host-timeout", "30s", public_ip]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            open_ports = []
            for line in proc.stdout.splitlines():
                m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line.strip())
                if m:
                    port = int(m.group(1))
                    service = m.group(2)
                    open_ports.append({"port": port, "service": service, "label": RISKY_PORTS.get(port, service)})
            result["open_ports"] = open_ports
            self.stats["perimeter_open_ports"] = open_ports
            self.stats["perimeter_last"] = result["ts"]
            for op in open_ports:
                if op["port"] in (23, 445, 3389, 5900, 6379, 27017, 21):
                    self.raise_event("perimeter", "critical", f"Offener riskanter Port {op['port']}/{op['label']}", f"Öffentliche IP {public_ip} exponiert {op['label']} (Port {op['port']}). Sofort schließen oder hinter VPN legen.", ip=public_ip, source="perimeter_scan", auto_block=False, meta=op)
                elif op["port"] in (22, 80, 443, 8080, 8443):
                    self.raise_event("perimeter", "medium", f"Perimeter-Dienst offen: {op['port']}/{op['label']}", f"{public_ip}:{op['port']} antwortet. Prüfen, ob beabsichtigt und gehärtet.", ip=public_ip, source="perimeter_scan", auto_block=False, meta=op)
        except Exception as exp:
            result["error"] = str(exp)
            log.error("perimeter scan failed: %s", exp)
        self.perimeter = result
        self._save(self.perimeter_file, result)
        return result

    def refresh_threat_intel(self) -> dict:
        networks: list[str] = []
        sources: list[str] = []
        for feed in BLOCKLIST_FEEDS:
            try:
                r = requests.get(feed["url"], timeout=30)
                if not r.ok:
                    continue
                sources.append(feed["name"])
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";") or line.startswith("#"):
                        continue
                    part = line.split(";")[0].strip().split()[0]
                    try:
                        net = ipaddress.ip_network(part, strict=False)
                        networks.append(str(net))
                    except Exception:
                        continue
            except Exception as exp:
                log.warning("threat feed %s failed: %s", feed["name"], exp)
        networks = sorted(set(networks))
        self.intel = {"updated": _now(), "sources": sources, "networks": networks, "count": len(networks)}
        self.stats["threat_intel_count"] = len(networks)
        self.stats["threat_intel_updated"] = self.intel["updated"]
        self._save(self.intel_file, self.intel)
        log.info("Threat intel refreshed: %d networks from %s", len(networks), sources)
        return self.intel

    def ip_in_threat_intel(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return None
        for net_s in self.intel.get("networks") or []:
            try:
                if addr in ipaddress.ip_network(net_s, strict=False):
                    return {"network": net_s, "ip": ip}
            except Exception:
                continue
        return None

    def check_peer_reputation(self, ip: str, context: str = "connection") -> dict | None:
        if _is_private(ip):
            return None
        hit = self.ip_in_threat_intel(ip)
        if not hit:
            return None
        return self.raise_event("threat_intel", "high", f"Bekannte Schad-IP: {ip}", f"IP {ip} steht auf Threat-Intelligence-Listen ({hit['network']}). Kontext: {context}", ip=ip, source="threat_intel", auto_block=True, meta=hit)

    def observe_device(self, device: dict) -> list[dict]:
        alerts = []
        mac = (device.get("mac") or "").upper()
        ip = device.get("ip") or ""
        if not mac or not ip:
            return alerts
        history = self.mac_history.setdefault(mac, [])
        if ip not in history:
            history.append(ip)
            self.mac_history[mac] = history[-5:]
            self._save(self.mac_history_file, self.mac_history)
            if len(history) > 1:
                evt = self.raise_event("mac_anomaly", "medium", f"MAC-IP-Wechsel: {mac}", f"Gerät {mac} nutzte zuvor {history[:-1]}, jetzt {ip}. Mögliches MAC-Spoofing oder DHCP-Wechsel.", ip=ip, mac=mac, source="lan_monitor", auto_block=False, meta={"history": list(history)})
                alerts.append(evt)
        return alerts

    def detect_ip_mac_conflict(self, devices: list[dict]) -> list[dict]:
        by_ip: dict[str, set[str]] = {}
        for d in devices:
            ip, mac = d.get("ip"), (d.get("mac") or "").upper()
            if ip and mac:
                by_ip.setdefault(ip, set()).add(mac)
        alerts = []
        for ip, macs in by_ip.items():
            if len(macs) > 1:
                alerts.append(self.raise_event("mac_spoof", "high", f"IP-Konflikt / mögliches Spoofing: {ip}", f"IP {ip} wird von mehreren MACs beansprucht: {', '.join(sorted(macs))}", ip=ip, source="lan_monitor", auto_block=True, meta={"macs": sorted(macs)}))
        return alerts

    def ingest_external_alert(self, payload: dict) -> dict:
        src = payload.get("src_ip") or payload.get("source_ip") or payload.get("src")
        dst = payload.get("dest_ip") or payload.get("destination_ip") or payload.get("dst")
        rule = payload.get("rule")
        sig = payload.get("signature") or (rule.get("description") if isinstance(rule, dict) else rule) or payload.get("message") or payload.get("alert") or "external IDS alert"
        sev_raw = str(payload.get("severity") or payload.get("alert_severity") or "high").lower()
        severity = "critical" if sev_raw in ("1", "critical", "4") else ("high" if sev_raw in ("2", "high", "3") else "medium")
        block_ip = None
        for candidate in (src, dst):
            if candidate and not _is_private(str(candidate)):
                block_ip = str(candidate)
                break
        if not block_ip and src:
            block_ip = str(src)
        return self.raise_event("ids", severity, f"IDS: {str(sig)[:120]}", json.dumps(payload, ensure_ascii=False)[:500], ip=block_ip, source=payload.get("sensor") or payload.get("source") or "external_ids", auto_block=True, meta=payload)

    def start_background(self) -> None:
        def _loop():
            try:
                self.refresh_threat_intel()
            except Exception as exp:
                log.error("initial threat intel: %s", exp)
            try:
                self.scan_perimeter()
            except Exception as exp:
                log.error("initial perimeter: %s", exp)
            last_intel = time.time()
            last_perim = time.time()
            while not self._stop.is_set():
                now = time.time()
                if now - last_intel >= self.threat_intel_interval:
                    try:
                        self.refresh_threat_intel()
                    except Exception as exp:
                        log.error("threat intel refresh: %s", exp)
                    last_intel = now
                if now - last_perim >= self.perimeter_interval:
                    try:
                        self.scan_perimeter()
                    except Exception as exp:
                        log.error("perimeter scan: %s", exp)
                    last_perim = now
                self._stop.wait(30)
        t = threading.Thread(target=_loop, name="security-engine", daemon=True)
        t.start()
        log.info("SecurityEngine started (perimeter every %ss, intel every %ss)", self.perimeter_interval, self.threat_intel_interval)

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        return {**self.stats, "auto_block": self.auto_block, "perimeter": self.perimeter, "threat_intel_sources": self.intel.get("sources"), "threat_intel_updated": self.intel.get("updated"), "recent_events": self.list_events(10)}
