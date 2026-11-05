# Changelog

## 2.2.1 – HA Store visibility + capture stack
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
- Host-side **Wireshark Extcap** script shipped in `/extcap/` (copy to your desktop Wireshark)
- Recommended companion: [FRITZ!Portal](https://github.com/jayjojayson/FRITZ-Portal) for rich live dashboard & topology
- Version bump to 2.2.0

## 2.1.0
- fritz_insights TR-064 log/WAN/ports/WLAN module

## 2.0.0 – Safety & Visibility rewrite
- Modes: `learning` | `monitor` | `enforce` (default **learning**)
- Hard protected devices (whitelist, HA host, gateway, Fritz, local IPs) – never blocked
- Circuit breaker: empty/shrunk host list, Fritz down, max blocks per cycle
- Identity by MAC; DHCP rebind re-applies WAN block; randomized/LAA MACs never auto-blocked
- Atomic `/data/state.json`, append-only `/data/audit.jsonl`, startup reconcile via `GetWANAccessByIP`
- Fritz client: HTTPS:49443 option, auth backoff, session reuse
- API: Ingress-only (no host port), optional `api_token`, CSRF, input validation, security headers
- Risk score with factors; device inventory; router port-mapping view; HA sensors/events
- Plain Python modules (no obfuscated payload for core logic)
- pytest coverage for policy and state

## 1.5.5
- Only actively connected devices auto-blocked / threat-detected

## 1.5.4
- Interface labels, event cooldown

## 1.3.0
- SecurityEngine perimeter / threat intel (optional, off by default in 2.0)
