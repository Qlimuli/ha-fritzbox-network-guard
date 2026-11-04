#!/usr/bin/env python3
"""Safety policy: modes, protected devices, circuit breaker, randomized MAC."""
from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("network-guard.policy")

MODES = ("learning", "monitor", "enforce")


def norm_mac(mac: str) -> str:
    m = (mac or "").upper().replace("-", ":").strip()
    if m.count(":") == 5:
        return m
    h = "".join(c for c in m if c.isalnum())
    if len(h) == 12:
        return ":".join(h[i : i + 2] for i in range(0, 12, 2)).upper()
    return m


def is_valid_mac(mac: str) -> bool:
    m = norm_mac(mac)
    if m.count(":") != 5:
        return False
    try:
        parts = m.split(":")
        return all(len(p) == 2 and 0 <= int(p, 16) <= 255 for p in parts)
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def is_randomized_mac(mac: str) -> bool:
    m = norm_mac(mac)
    try:
        return bool(int(m.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def local_ipv4s() -> set[str]:
    ips: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    ips.add("127.0.0.1")
    return ips


def default_gateway() -> str | None:
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    gw_hex = fields[2]
                    b = bytes.fromhex(gw_hex)
                    return ".".join(str(x) for x in reversed(b))
    except Exception as exc:
        log.debug("gateway resolve failed: %s", exc)
    return None


@dataclass
class PolicyConfig:
    mode: str = "learning"
    learning_days: int = 7
    whitelist_macs: set[str] = field(default_factory=set)
    whitelist_ips: set[str] = field(default_factory=set)
    max_blocks_per_cycle: int = 3
    dry_run: bool = False
    auto_block_new_devices: bool = False
    critical_mac_prefixes: list[str] = field(default_factory=list)
    notify_threshold: int = 40
    block_threshold: int = 70
    fritzbox_host: str = "fritz.box"

    def __post_init__(self) -> None:
        self.mode = (self.mode or "learning").lower()
        if self.mode not in MODES:
            self.mode = "learning"
        self.whitelist_macs = {norm_mac(m) for m in self.whitelist_macs if m}
        self.whitelist_ips = {str(i).strip() for i in self.whitelist_ips if i}
        self.critical_mac_prefixes = [
            p.strip().upper().replace("-", ":")
            for p in self.critical_mac_prefixes
            if p and p.strip()
        ]


class SafetyPolicy:
    def __init__(self, cfg: PolicyConfig):
        self.cfg = cfg
        self._prev_host_count: int | None = None
        self._protected_ips: set[str] = set()
        self._protected_macs: set[str] = set()
        self.refresh_protected()

    def refresh_protected(self) -> None:
        ips = set(self.cfg.whitelist_ips)
        ips |= local_ipv4s()
        gw = default_gateway()
        if gw:
            ips.add(gw)
        try:
            host = self.cfg.fritzbox_host
            if host and not is_valid_ipv4(host):
                for info in socket.getaddrinfo(host, None, socket.AF_INET):
                    ips.add(info[4][0])
            elif host and is_valid_ipv4(host):
                ips.add(host)
        except Exception:
            pass
        ips.add("192.168.178.1")
        self._protected_ips = ips
        self._protected_macs = set(self.cfg.whitelist_macs)
        log.info("Protected IPs=%d MACs=%d gateway=%s", len(self._protected_ips), len(self._protected_macs), gw)

    def is_whitelisted(self, ip: str, mac: str) -> bool:
        mac_n = norm_mac(mac)
        if ip and ip in self.cfg.whitelist_ips:
            return True
        if mac_n and mac_n in self.cfg.whitelist_macs:
            return True
        return False

    def is_protected(self, ip: str, mac: str) -> tuple[bool, str]:
        mac_n = norm_mac(mac)
        if mac_n and mac_n in self._protected_macs:
            return True, "whitelist_mac"
        if ip and ip in self._protected_ips:
            return True, "protected_ip"
        if self.is_whitelisted(ip, mac):
            return True, "whitelist"
        if ip and ip in local_ipv4s():
            return True, "local_host"
        return False, ""

    def is_critical_prefix(self, mac: str) -> bool:
        mac_n = norm_mac(mac)
        return any(mac_n.startswith(p) for p in self.cfg.critical_mac_prefixes) if mac_n else False

    def circuit_breaker(self, host_count: int, fritz_ok: bool, pending_blocks: int) -> tuple[bool, str]:
        if not fritz_ok:
            return True, "fritzbox_unreachable"
        if host_count == 0:
            return True, "empty_host_list"
        if self._prev_host_count is not None and self._prev_host_count > 0:
            if host_count < self._prev_host_count * 0.5:
                reason = f"host_list_shrank:{self._prev_host_count}->{host_count}"
                self._prev_host_count = host_count
                return True, reason
        self._prev_host_count = host_count
        if pending_blocks > self.cfg.max_blocks_per_cycle:
            return True, f"max_blocks_exceeded:{pending_blocks}>{self.cfg.max_blocks_per_cycle}"
        return False, ""

    def allow_auto_block(self, *, ip: str, mac: str, is_new: bool, active: bool, learning_complete: bool) -> tuple[bool, str]:
        if not active:
            return False, "inactive"
        if is_randomized_mac(mac):
            return False, "randomized_mac"
        protected, why = self.is_protected(ip, mac)
        if protected:
            return False, f"protected:{why}"
        if self.cfg.mode == "learning":
            return False, "mode_learning"
        if self.cfg.mode == "monitor":
            return False, "mode_monitor"
        if is_new and self.cfg.auto_block_new_devices:
            return True, "new_unknown_device"
        if self.is_critical_prefix(mac):
            return True, "critical_mac_prefix"
        return False, "no_rule"

    def allow_manual_block(self, ip: str, mac: str) -> tuple[bool, str]:
        protected, why = self.is_protected(ip, mac)
        if protected:
            return False, f"protected:{why}"
        return True, "manual"
