#!/usr/bin/env python3
"""Transparent risk score 0-100 with contributing factors."""
from __future__ import annotations

from policy import is_randomized_mac, norm_mac

# port -> (points, label)
PORT_RISK = {
    23: (30, "Telnet"),
    21: (25, "FTP"),
    554: (20, "RTSP"),
    445: (15, "SMB"),
    139: (15, "NetBIOS"),
    135: (15, "MSRPC"),
    3389: (25, "RDP"),
    5900: (20, "VNC"),
    1900: (10, "UPnP/SSDP"),
    5000: (10, "UPnP alt"),
    80: (10, "HTTP admin (no TLS)"),
    8080: (10, "HTTP-Alt"),
    22: (5, "SSH"),
}


def score_device(
    *,
    open_ports: list[int] | None = None,
    critical_prefix: bool = False,
    is_new: bool = False,
    mac: str = "",
    status: str = "",
) -> tuple[int, list[dict]]:
    factors: list[dict] = []
    total = 0
    for port in open_ports or []:
        if port in PORT_RISK:
            pts, label = PORT_RISK[port]
            factors.append({"code": f"port_{port}", "points": pts, "label": label})
            total += pts
    if critical_prefix:
        factors.append({"code": "critical_mac", "points": 25, "label": "Critical MAC prefix"})
        total += 25
    if is_new:
        factors.append({"code": "new_device", "points": 10, "label": "New device"})
        total += 10
    if mac and is_randomized_mac(mac):
        factors.append({"code": "randomized_mac", "points": 5, "label": "Randomized/LAA MAC"})
        total += 5
    if status == "guest":
        factors.append({"code": "guest", "points": 5, "label": "Guest network"})
        total += 5
    total = max(0, min(100, total))
    return total, factors
