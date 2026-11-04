#!/usr/bin/env python3
"""FritzBox TR-064 insights: device log, WAN, port mappings, WLAN.

Only documented AVM actions are used. Log content is fetched via the path
returned by DeviceInfo1.X_AVM-DE_GetDeviceLogPath (HTTP, same credentials).
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urljoin

import requests

log = logging.getLogger("fritz-insights")

LOG_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("auth_fail", "high", re.compile(r"(anmeldung|login|authentication).*(fehl|fail|wrong|ungültig|invalid|abgewiesen)", re.I)),
    ("auth_fail", "high", re.compile(r"(fehlgeschlagen|failed).*(anmeldung|login|authentication)", re.I)),
    ("vpn", "medium", re.compile(r"(vpn|wireguard|ipsec|pptp|l2tp)", re.I)),
    ("config_change", "medium", re.compile(r"(einstellung|configuration|settings).*(geändert|changed|saved|gespeichert)", re.I)),
    ("port_forward", "medium", re.compile(r"(portfreigabe|port\s*forward|port mapping|freigabe)", re.I)),
    ("firmware", "low", re.compile(r"(firmware|fritz!?\s*os).*(update|aktual)", re.I)),
    ("wlan", "low", re.compile(r"(wlan|wifi|wireless).*(an|aus|on|off|aktiv|deaktiv)", re.I)),
    ("internet", "medium", re.compile(r"(internetverbindung|ppp|dsl).*(getrennt|disconnect|down|fehler|fail)", re.I)),
    ("new_device", "medium", re.compile(r"(neues gerät|new device|angemeldet|registered)", re.I)),
    ("block", "low", re.compile(r"(gesperrt|blocked|filter|kindersicherung|parental)", re.I)),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FritzInsights:
    def __init__(self, get_fritz: Callable, host: str = "fritz.box"):
        self._get_fritz = get_fritz
        self.host = host.rstrip("/")
        self._log_cache: dict[str, Any] = {"ts": 0.0, "raw": ""}

    def _fc(self):
        return self._get_fritz()

    def _call(self, service: str, action: str, arguments: dict | None = None) -> dict:
        fc = self._fc()
        try:
            return fc.call_action(service, action, arguments=arguments or {})
        except Exception:
            alt = service[:-1] if service.endswith("1") else service + "1"
            return fc.call_action(alt, action, arguments=arguments or {})

    def _fetch_raw_log(self) -> str:
        now = time.time()
        if self._log_cache["raw"] and now - self._log_cache["ts"] < 30:
            return self._log_cache["raw"]
        path = ""
        try:
            res = self._call("DeviceInfo1", "X_AVM-DE_GetDeviceLogPath")
            path = (
                res.get("NewDeviceLogPath")
                or res.get("NewX_AVM-DE_DeviceLogPath")
                or res.get("DeviceLogPath")
                or ""
            )
        except Exception as exc:
            log.warning("X_AVM-DE_GetDeviceLogPath failed: %s", exc)
            try:
                res = self._call("DeviceInfo1", "GetDeviceLog")
                text = res.get("NewDeviceLog") or res.get("DeviceLog") or ""
                if text:
                    self._log_cache = {"ts": now, "raw": text}
                    return text
            except Exception as exc2:
                log.warning("GetDeviceLog fallback failed: %s", exc2)
                raise RuntimeError(f"Device log unavailable: {exc}") from exc

        if not path:
            raise RuntimeError("Empty device log path from FritzBox")

        fc = self._fc()
        user = getattr(fc, "user", None) or ""
        password = getattr(fc, "password", None) or ""
        base = f"http://{self.host}"
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = requests.get(url, auth=(user, password) if user or password else None, timeout=20, verify=False)
            r.raise_for_status()
            text = r.text
        except Exception:
            url2 = urljoin(f"https://{self.host}/", path.lstrip("/"))
            r = requests.get(url2, auth=(user, password) if user or password else None, timeout=20, verify=False)
            r.raise_for_status()
            text = r.text
        self._log_cache = {"ts": now, "raw": text}
        return text

    def _parse_log_lines(self, raw: str, limit: int = 80) -> list[dict]:
        events: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(
                r"^(\d{1,2}\.\d{1,2}\.\d{2,4}\s+\d{1,2}:\d{2}:\d{2})\s+(.*)$",
                line,
            )
            if m:
                ts_s, msg = m.group(1), m.group(2)
            else:
                ts_s, msg = "", line
            group, severity = "other", "info"
            for g, sev, pat in LOG_PATTERNS:
                if pat.search(msg):
                    group, severity = g, sev
                    break
            events.append({"ts": ts_s, "message": msg, "group": group, "severity": severity, "raw": line})
        events = list(reversed(events))
        return events[: max(10, limit)]

    def get_device_log(self, filter_group: str = "all", limit: int = 80, use_cache_sec: int = 0) -> dict[str, Any]:
        if use_cache_sec and self._log_cache["raw"] and time.time() - self._log_cache["ts"] < use_cache_sec:
            raw = self._log_cache["raw"]
        else:
            raw = self._fetch_raw_log()
        events = self._parse_log_lines(raw, limit=500)
        groups: dict[str, int] = {}
        for e in events:
            groups[e["group"]] = groups.get(e["group"], 0) + 1
        if filter_group and filter_group != "all":
            events = [e for e in events if e["group"] == filter_group]
        events = events[:limit]
        analysis = {
            "auth_failures": groups.get("auth_fail", 0),
            "vpn_events": groups.get("vpn", 0),
            "config_changes": groups.get("config_change", 0),
            "port_forward_events": groups.get("port_forward", 0),
            "high_severity": sum(1 for e in events if e["severity"] == "high"),
            "total_parsed": sum(groups.values()),
        }
        return {
            "ok": True,
            "filter": filter_group,
            "count": len(events),
            "events": events,
            "groups": groups,
            "analysis": analysis,
            "fetched_at": _now(),
        }

    def get_wan_status(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": True, "fetched_at": _now()}
        for svc in ("WANIPConnection1", "WANPPPConnection1"):
            try:
                r = self._call(svc, "GetExternalIPAddress")
                out["external_ip"] = r.get("NewExternalIPAddress") or r.get("ExternalIPAddress")
                out["wan_service"] = svc
                break
            except Exception:
                continue
        for svc in ("WANIPConnection1", "WANPPPConnection1"):
            try:
                r = self._call(svc, "GetStatusInfo")
                out["connection_status"] = r.get("NewConnectionStatus") or r.get("ConnectionStatus")
                out["uptime"] = r.get("NewUptime") or r.get("Uptime")
                out["last_error"] = r.get("NewLastConnectionError") or r.get("LastConnectionError")
                break
            except Exception:
                continue
        try:
            r = self._call("WANCommonInterfaceConfig1", "GetTotalBytesSent")
            out["bytes_sent"] = r.get("NewTotalBytesSent") or r.get("TotalBytesSent")
        except Exception:
            pass
        try:
            r = self._call("WANCommonInterfaceConfig1", "GetTotalBytesReceived")
            out["bytes_received"] = r.get("NewTotalBytesReceived") or r.get("TotalBytesReceived")
        except Exception:
            pass
        try:
            r = self._call("DeviceInfo1", "GetInfo")
            out["firmware"] = r.get("NewSoftwareVersion") or r.get("SoftwareVersion")
            out["model"] = r.get("NewModelName") or r.get("ModelName")
            out["serial"] = r.get("NewSerialNumber") or r.get("SerialNumber")
        except Exception as exp:
            out["deviceinfo_error"] = str(exp)
        try:
            r = self._call("UserInterface1", "GetInfo")
            out["upgrade_available"] = r.get("NewUpgradeAvailable") or r.get("UpgradeAvailable")
        except Exception:
            out["upgrade_available"] = None
        return out

    def get_port_mappings(self, max_entries: int = 64) -> dict[str, Any]:
        mappings: list[dict] = []
        errors: list[str] = []
        for svc in ("WANIPConnection1", "WANPPPConnection1"):
            for idx in range(max_entries):
                try:
                    r = self._call(svc, "GetGenericPortMappingEntry", {"NewPortMappingIndex": idx})
                except Exception as exp:
                    if idx == 0:
                        errors.append(f"{svc}: {exp}")
                    break
                entry = {
                    "index": idx,
                    "service": svc,
                    "external_port": r.get("NewExternalPort") or r.get("ExternalPort"),
                    "protocol": r.get("NewProtocol") or r.get("Protocol"),
                    "internal_port": r.get("NewInternalPort") or r.get("InternalPort"),
                    "internal_client": r.get("NewInternalClient") or r.get("InternalClient"),
                    "enabled": r.get("NewEnabled") or r.get("Enabled"),
                    "description": r.get("NewPortMappingDescription") or r.get("PortMappingDescription") or "",
                    "lease": r.get("NewLeaseDuration") or r.get("LeaseDuration"),
                }
                desc = (entry["description"] or "").lower()
                entry["likely_upnp"] = not desc or "upnp" in desc or "application" in desc
                mappings.append(entry)
            if mappings:
                break
        return {"ok": True, "count": len(mappings), "mappings": mappings, "errors": errors, "fetched_at": _now()}

    def get_wlan_status(self) -> dict[str, Any]:
        networks: list[dict] = []
        for i in range(1, 5):
            svc = f"WLANConfiguration{i}"
            try:
                info = self._call(svc, "GetInfo")
            except Exception:
                continue
            try:
                ssid = self._call(svc, "GetSSID")
                ssid_val = ssid.get("NewSSID") or ssid.get("SSID")
            except Exception:
                ssid_val = info.get("NewSSID") or info.get("SSID")
            networks.append({
                "index": i,
                "ssid": ssid_val,
                "status": info.get("NewStatus") or info.get("Status"),
                "channel": info.get("NewChannel") or info.get("Channel"),
                "standard": info.get("NewStandard") or info.get("Standard"),
                "beacon_type": info.get("NewBeaconType") or info.get("BeaconType"),
            })
        return {"ok": True, "count": len(networks), "networks": networks, "fetched_at": _now()}
