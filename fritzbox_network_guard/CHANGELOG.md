# Changelog

## 2.2.4 – Full GUI fix (load + clickable)
- Complete multi-tab UI restored as single self-contained `ui.html` (no broken partial assembly)
- run.sh now prefers the complete ui.html (>15 KB) and only falls back to ui_parts when missing
- Tabs: Übersicht, Geräte, Gesperrt, Security, Fritz/Logs, Traffic (Capture), Whitelist, Einstellungen
- All buttons, filters, capture controls and log loaders are interactive again
- Version bump so Home Assistant Supervisor picks up the update

## 2.2.3
- Version bump + robust ui_parts assembly attempt

## 2.2.2 / 2.2.1 – HA Store visibility + capture stack
- Packet capture API with web SID login (`login_sid.lua`)
- `/api/capture/*` routes (start/stop/list/analyze/download)
- `packet_capture.py` + tshark in image
- Host-side Wireshark Extcap under `extcap/`
- Companion note: FRITZ!Portal

## 2.2.0 – Packet Capture & Traffic Analysis
- Wireshark-compatible packet capture via FritzBox hidden capture endpoint
- New module `packet_capture.py`
- Lightweight analysis with tshark
- Host-side Wireshark Extcap

## 2.1.0
- fritz_insights TR-064 log/WAN/ports/WLAN module

## 2.0.0 – Safety & Visibility rewrite
- Modes: learning | monitor | enforce
- Hard protected devices, circuit breaker, MAC identity
- Atomic state, audit log, Ingress-only API
