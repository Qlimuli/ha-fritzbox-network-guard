#!/usr/bin/env python3
"""Detailed analysis helpers for security detections."""
from __future__ import annotations

OUI_VENDORS = {
    "00:1A:79": "AVM (FRITZ!)", "00:1C:4A": "AVM", "9C:C7:A6": "AVM", "C8:0E:14": "AVM",
    "2C:91:AB": "AVM", "3C:A6:2F": "AVM", "DC:39:6F": "AVM", "E0:28:6D": "AVM",
    "98:9B:CB": "AVM", "44:4E:6D": "AVM",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft/Hyper-V", "00:50:F2": "Microsoft",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips",
    "18:FE:34": "Espressif", "24:0A:C4": "Espressif", "30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif", "5C:CF:7F": "Espressif", "A4:7B:9D": "Espressif",
    "B4:E6:2D": "Espressif", "CC:50:E3": "Espressif", "DC:4F:22": "Espressif",
    "F0:5C:77": "Google", "3C:5A:B4": "Google", "54:60:09": "Google", "F4:F5:D8": "Google",
    "18:B4:30": "Nest", "64:16:66": "Nest", "B0:0B:D0": "Samsung",
    "00:1B:21": "Intel", "3C:97:0E": "Intel", "F8:63:3F": "Intel",
    "00:E0:18": "ASUS", "04:D4:C4": "ASUS", "2C:4D:54": "ASUS", "50:46:5D": "ASUS",
    "AC:22:0B": "ASUS", "F4:6D:04": "ASUS",
    "00:25:00": "Apple", "AC:87:A3": "Apple", "F0:D1:A9": "Apple", "A4:83:E7": "Apple",
    "F4:5C:89": "Apple", "3C:15:C2": "Apple", "D0:03:4B": "Apple", "BC:67:78": "Apple",
    "F0:18:98": "Apple", "88:66:A5": "Apple", "28:CF:E9": "Apple",
}


def vendor_from_mac(mac: str) -> str:
    m = (mac or "").upper().replace("-", ":").strip()
    if m.count(":") != 5:
        return "unbekannt"
    prefix = ":".join(m.split(":")[:3])
    if prefix in OUI_VENDORS:
        return OUI_VENDORS[prefix]
    try:
        first = int(m.split(":")[0], 16)
        if first & 0x02:
            return "lokal/virtuell (LAA)"
    except Exception:
        pass
    return "unbekannt"


def is_locally_administered(mac: str) -> bool:
    m = (mac or "").upper().replace("-", ":").strip()
    try:
        return bool(int(m.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def analyze_mac_spoof(ip: str, macs: list, devices: list | None = None) -> dict:
    device_by_mac = {}
    if devices:
        for d in devices:
            m = (d.get("mac") or "").upper().replace("-", ":")
            if m:
                device_by_mac[m] = d
    mac_details = []
    laa_count = 0
    vendors = set()
    names = []
    for mac in sorted(macs):
        v = vendor_from_mac(mac)
        vendors.add(v)
        laa = is_locally_administered(mac)
        if laa:
            laa_count += 1
        d = device_by_mac.get(mac, {})
        name = d.get("name") or d.get("hostname") or d.get("host") or ""
        if name:
            names.append(name)
        mac_details.append({
            "mac": mac, "vendor": v, "locally_administered": laa,
            "name": name or None,
            "interface": d.get("interface") or d.get("conn") or d.get("type"),
            "active": d.get("active", d.get("online")),
        })
    causes = []
    confidence = "mittel"
    if laa_count >= 1:
        causes.append(
            "Mindestens eine MAC ist lokal vergeben (LAA) – typisch für VMs, Container, "
            "VPN, randomisierte WLAN-MACs (iOS/Android) oder Spoofing."
        )
    if len(vendors) > 1 and "unbekannt" not in vendors:
        causes.append("Unterschiedliche Hersteller-OUIs auf derselben IP – ungewöhnlich für ein Gerät.")
        confidence = "hoch"
    if all(is_locally_administered(m) for m in macs):
        causes.append(
            "Alle MACs sind lokal administriert – oft VPN/Hotspot, Docker, Hypervisor "
            "oder Privacy-MAC-Rotation."
        )
        confidence = "mittel"
    if not causes:
        causes.append(
            "Mögliche Ursachen: DHCP-Lease-Übernahme, ARP-Spoofing, Mesh-Repeater mit "
            "Proxy-ARP, zwei Geräte mit fester IP, oder FritzBox-Gäste/LAN-Doppelmeldung."
        )
    recommendations = [
        f"In der FritzBox unter Heimnetz → Netzwerk die IP {ip} und alle zugehörigen Geräte prüfen.",
        "ARP-Tabelle der FritzBox bzw. arp -a auf einem Client vergleichen.",
        "Ob die IP statisch vergeben ist und ob zwei Geräte dieselbe Adresse nutzen.",
        "Bei Gäste-WLAN/Mesh: Doppelmeldungen können harmlos sein – dann Whitelist nutzen.",
        "Bei Verdacht auf Spoofing: betroffene MACs isolieren (WAN-Sperre / MAC-Filter) und Logs prüfen.",
    ]
    if laa_count:
        recommendations.append(
            "LAA-MACs: prüfen ob Smartphone-Privatadresse, VM oder IoT-Bridge (z.B. ESP/Docker)."
        )
    return {
        "type": "mac_spoof", "ip": ip, "mac_count": len(macs), "macs": mac_details,
        "vendors": sorted(vendors), "device_names": names, "confidence": confidence,
        "possible_causes": causes, "recommendations": recommendations,
        "summary": (
            f"IP {ip} wird von {len(macs)} MACs beansprucht "
            f"({', '.join(f'{m} [{vendor_from_mac(m)}]' for m in sorted(macs))}). "
            f"Einschätzung: {confidence}."
        ),
    }


def analyze_mac_anomaly(mac: str, history: list, ip: str) -> dict:
    vendor = vendor_from_mac(mac)
    laa = is_locally_administered(mac)
    causes = [
        "DHCP hat eine neue Adresse vergeben (Lease abgelaufen / Router-Neustart).",
        "Gerät war in einem anderen VLAN/Gastnetz und ist zurückgekehrt.",
    ]
    if laa:
        causes.append("Privatadresse/Random-MAC: OS wechselt OUI-ähnliche Adressen periodisch.")
    causes.append("Mögliches MAC-Spoofing: Angreifer übernimmt Identität eines bekannten Geräts.")
    return {
        "type": "mac_anomaly", "mac": mac, "vendor": vendor, "locally_administered": laa,
        "ip_history": list(history), "current_ip": ip,
        "confidence": "niedrig" if laa or len(history) <= 2 else "mittel",
        "possible_causes": causes,
        "recommendations": [
            "Prüfen, ob der IP-Wechsel mit DHCP-Lease oder Netzwechsel zusammenfällt.",
            "Hostname/Hersteller in der FritzBox mit dem erwarteten Gerät abgleichen.",
            "Bei unerwartetem Wechsel: Gerät isolieren und Fritz-Ereignisprotokoll prüfen.",
        ],
        "summary": f"MAC {mac} ({vendor}) wechselte IP-Historie {history[:-1]} → {ip}.",
    }


def analyze_threat_intel(ip: str, hit: dict, context: str) -> dict:
    return {
        "type": "threat_intel", "ip": ip, "matched_network": hit.get("network"),
        "context": context, "confidence": "hoch",
        "possible_causes": [
            "IP steht auf öffentlichen Blocklists (FireHOL / Spamhaus DROP/EDROP).",
            "Bekannte C2-, Scan- oder Spam-Quelle – Verbindung sollte unterbunden werden.",
        ],
        "recommendations": [
            "Ausgehende Verbindung zu dieser IP blockieren (WAN-Sperre).",
            "Welches lokale Gerät kommuniziert damit? (FritzBox Online-Monitor / Verbindungen).",
            "Falls Fehlalarm (CDN/Shared Hosting): Ausnahme dokumentieren und Whitelist.",
        ],
        "summary": f"Schad-IP {ip} matched {hit.get('network')} (Kontext: {context}).",
    }


def analyze_perimeter(public_ip: str, port_info: dict) -> dict:
    port = port_info.get("port")
    label = port_info.get("label") or port_info.get("service")
    critical = port in (23, 445, 3389, 5900, 6379, 27017, 21)
    return {
        "type": "perimeter", "public_ip": public_ip, "port": port, "service": label,
        "confidence": "hoch",
        "possible_causes": [
            "Portweiterleitung auf der FritzBox aktiv.",
            "Gerät mit UPnP hat den Port geöffnet.",
            "Absichtlich exponierter Dienst (NAS, VPN, Web).",
        ],
        "recommendations": [
            "In FritzBox → Internet → Freigaben Portweiterleitungen prüfen und unnötige schließen.",
            "UPnP deaktivieren, wenn nicht benötigt.",
            "Kritische Dienste nur über VPN erreichbar machen.",
            f"Dienst auf Port {port} ({label}) härten oder hinter Authentifizierung legen.",
        ],
        "severity_hint": "critical" if critical else "medium",
        "summary": f"Öffentliche IP {public_ip} exponiert {label} auf Port {port}.",
    }
