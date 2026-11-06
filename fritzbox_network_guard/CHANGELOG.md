# Changelog

## 2.2.6 – GUI bleibt nicht mehr auf „Laden…“
- Ingress-Base-Pfad (`__BASE__`) zuverlässig aus `location.pathname`
- API-Calls mit 12s Timeout (kein endloses Hängen mehr)
- Übersicht lädt soft: ein kaputter Endpoint blockiert nicht die ganze Seite
- Fehler sichtbar im Header statt ewig „Laden…“
- Console-Log: `[NetworkGuard] __BASE__=…`

## 2.2.5 – Ingress API-Pfade
- Relative API-URLs unter HA Ingress
- Capture-Download relativ

## 2.2.4 – Full GUI fix (load + clickable)
- Complete multi-tab UI restored
- Tabs: Übersicht, Geräte, Gesperrt, Security, Fritz/Logs, Traffic, Whitelist, Einstellungen

## 2.2.3
- Version bump + robust ui_parts assembly

## 2.2.2 / 2.2.1 – Capture stack
- Packet capture API + SID login
- tshark / Wireshark Extcap

## 2.2.0 – Packet Capture & Traffic Analysis
## 2.1.0 – fritz_insights
## 2.0.0 – Safety & Visibility rewrite
