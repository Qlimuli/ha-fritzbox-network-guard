# Changelog

## 2.2.3 – Full multi-tab GUI restored
- Complete Ingress UI with 8 tabs: Übersicht, Geräte, Gesperrt, Security, Fritz/Logs, Traffic (Capture), Whitelist, Einstellungen
- Logs, statistics, security events, Fritz event log filters, WAN/ports/WLAN insights
- Packet capture start/stop/list/analyze/download with tshark hierarchy
- Manual block/unblock, whitelist, force scan, perimeter, threat-intel, deep scan
- Version bump so Home Assistant Supervisor picks up the update

## 2.2.2 / 2.2.1 – HA Store visibility + capture stack
- Version bump so Home Assistant Supervisor picks up the update
- Packet capture API with web SID login (`login_sid.lua`)
- `/api/capture/*` routes (start/stop/list/analyze/download)
- `packet_capture.py` + tshark in image
- Host-side Wireshark Extcap under `extcap/`
- Companion note: FRITZ!Portal

## 2.2.0 – Packet Capture & Traffic Analysis
- **Wireshark-compatible packet capture** via FritzBox hidden capture endpoint (`/cgi-bin/capture_notimeout`)
- New module `packet_capture.py`: start/stop capture on selectable interfaces (LAN, WAN, WLAN, physical ports)
- PCAP files stored under `/data/captures`, downloadable from the UI
- Lightweight analysis with `tshark` (protocol hierarchy, endpoints/top talkers, packet preview)
- Dockerfile now includes `tshark`, `tcpdump`, `wireshark-common`
- Host-side **Wireshark Extcap** script shipped in `/extcap/`
- Recommended companion: [FRITZ!Portal](https://github.com/jayjojayson/FRITZ-Portal)

## 2.1.0
- fritz_insights TR-064 log/WAN/ports/WLAN module

## 2.0.0 – Safety & Visibility rewrite
- Modes: `learning` | `monitor` | `enforce` (default **learning**)
- Hard protected devices (whitelist, HA host, gateway, Fritz, local IPs) – never blocked
- Circuit breaker, MAC identity, dry-run, Ingress-only API
