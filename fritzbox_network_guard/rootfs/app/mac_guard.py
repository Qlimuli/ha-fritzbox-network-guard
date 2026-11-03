"""FritzBox dynamic MAC quarantine helpers."""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Callable

import requests

log = logging.getLogger("network-guard.mac")


def norm_mac(mac: str) -> str:
    return (mac or "").upper().replace("-", ":").strip()


class MacQuarantine:
    """Enable MAC filter only while devices are blocked; whitelist all known except blocked."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        get_fritz: Callable,
        scan_stats: dict,
    ):
        self.host = host
        self.user = user or ""
        self.password = password or ""
        self.get_fritz = get_fritz
        self.scan_stats = scan_stats

    def _base(self) -> str:
        h = self.host
        if not h.startswith("http"):
            h = f"http://{h}"
        return h.rstrip("/")

    def web_sid(self) -> str | None:
        try:
            base = self._base()
            r = requests.get(f"{base}/login_sid.lua", timeout=10)
            r.raise_for_status()
            challenge = re.search(r"<Challenge>([^<]+)</Challenge>", r.text)
            sid_m = re.search(r"<SID>([^<]+)</SID>", r.text)
            if not challenge:
                return None
            ch = challenge.group(1)
            if sid_m and sid_m.group(1) != "0000000000000000":
                return sid_m.group(1)
            resp = hashlib.md5((ch + "-" + self.password).encode("utf-16le")).hexdigest()
            r2 = requests.get(
                f"{base}/login_sid.lua",
                params={"username": self.user, "response": f"{ch}-{resp}"},
                timeout=10,
            )
            sid_m = re.search(r"<SID>([^<]+)</SID>", r2.text)
            if sid_m and sid_m.group(1) != "0000000000000000":
                return sid_m.group(1)
            log.warning("Fritz web SID login failed")
            return None
        except Exception as exc:
            log.warning("Fritz web SID error: %s", exc)
            return None

    def set_filter_enabled(self, enabled: bool) -> bool:
        ok = False
        try:
            fc = self.get_fritz()
            for svc in (
                "WLANConfiguration1",
                "WLANConfiguration2",
                "WLANConfiguration3",
                "WLANConfiguration4",
            ):
                try:
                    info = fc.call_action(svc, "GetInfo")
                    args = {
                        "NewMaxBitRate": info.get("NewMaxBitRate", "Auto"),
                        "NewChannel": info.get("NewChannel", 0),
                        "NewSSID": info.get("NewSSID", ""),
                        "NewBeaconType": info.get("NewBeaconType", "11i"),
                        "NewMACAddressControlEnabled": bool(enabled),
                        "NewBasicEncryptionModes": info.get("NewBasicEncryptionModes", "None"),
                        "NewBasicAuthenticationMode": info.get("NewBasicAuthenticationMode", "None"),
                    }
                    fc.call_action(svc, "SetConfig", arguments=args)
                    log.info("MAC filter %s on %s", "ON" if enabled else "OFF", svc)
                    ok = True
                except Exception as exc:
                    log.debug("MAC filter skip %s: %s", svc, exc)
        except Exception as exc:
            log.error("set_filter_enabled failed: %s", exp := exc)
        return ok

    def remove_mac(self, mac: str) -> bool:
        mac = norm_mac(mac)
        if not mac or mac.count(":") != 5:
            return False
        sid = self.web_sid()
        if not sid:
            return False
        base = self._base()
        parts = mac.split(":")
        attempts = [
            {
                "xhr": "1",
                "sid": sid,
                "lang": "de",
                "page": "wSet",
                "apply": "",
                "mac_filter": "on",
                f"macfilter_del_{mac}": "on",
                "delete": mac,
            },
            {
                "xhr": "1",
                "sid": sid,
                "lang": "de",
                "page": "wSet",
                "apply": "1",
                "macfilter": "1",
                "mac": mac,
                "mac0": parts[0],
                "mac1": parts[1],
                "mac2": parts[2],
                "mac3": parts[3],
                "mac4": parts[4],
                "mac5": parts[5],
                "btn_delete": "",
            },
            {
                "xhr": "1",
                "sid": sid,
                "lang": "de",
                "page": "netDev",
                "xhrId": "cleanup",
                "delete": mac,
                "useajax": "1",
            },
        ]
        for data in attempts:
            try:
                r = requests.post(f"{base}/data.lua", data=data, timeout=10)
                if r.status_code == 200:
                    log.info("Web remove MAC OK for %s (page=%s)", mac, data.get("page"))
                    return True
            except Exception as exc:
                log.debug("remove MAC %s: %s", mac, exp := exc)
        log.warning("Could not remove MAC %s from known list", mac)
        return False

    def ensure_mac_allowed(self, mac: str) -> bool:
        mac = norm_mac(mac)
        if not mac or mac.count(":") != 5:
            return False
        sid = self.web_sid()
        if not sid:
            return False
        base = self._base()
        parts = mac.split(":")
        data = {
            "xhr": "1",
            "sid": sid,
            "lang": "de",
            "page": "wKey",
            "mac": mac,
            "mac0": parts[0],
            "mac1": parts[1],
            "mac2": parts[2],
            "mac3": parts[3],
            "mac4": parts[4],
            "mac5": parts[5],
            "apply": "",
        }
        try:
            r = requests.post(f"{base}/data.lua", data=data, timeout=10)
            if r.status_code == 200:
                log.info("Ensured MAC allowed: %s", mac)
                return True
        except Exception as exp:
            log.debug("ensure MAC allowed failed: %s", exp)
        return False

    def apply(self, blocked_devices: dict, known_devices: dict) -> dict:
        """If blocked: enable MAC filter, allow all known except blocked. If empty: disable."""
        result: dict[str, Any] = {
            "filter_enabled": False,
            "removed": [],
            "allowed": [],
            "errors": [],
        }
        blocked_macs = {norm_mac(v.get("mac")) for v in blocked_devices.values() if v.get("mac")}
        blocked_macs.discard("")

        if not blocked_devices:
            if self.set_filter_enabled(False):
                result["filter_enabled"] = False
                self.scan_stats["mac_filter_active"] = False
                log.info("MAC filter DISABLED (no blocked devices)")
            else:
                result["errors"].append("disable_filter_failed")
            return result

        if not self.set_filter_enabled(True):
            result["errors"].append("enable_filter_failed")
        else:
            result["filter_enabled"] = True
            self.scan_stats["mac_filter_active"] = True
            log.info("MAC filter ENABLED (%d blocked)", len(blocked_devices))

        allowed_macs = set()
        for d in known_devices.values():
            m = norm_mac(d.get("mac") or "")
            if m and m not in blocked_macs:
                allowed_macs.add(m)

        for m in blocked_macs:
            if self.remove_mac(m):
                result["removed"].append(m)
            else:
                result["errors"].append(f"remove_failed:{m}")

        for m in allowed_macs:
            if self.ensure_mac_allowed(m):
                result["allowed"].append(m)

        return result
