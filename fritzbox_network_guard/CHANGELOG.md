# Changelog

## 2.4.2 – Update-Erkennung + UI-JS-Fix
- JS-Syntaxfehler in esc() behoben – Buttons und Tabs reagieren wieder
- Bottom-Navigation: Touch/Icons zuverlässig (pointer-events, touchend)
- Version-Bump in config.yaml + Dockerfile (root und Add-on-Ordner)

## 2.4.1 – Button-Zuverlässigkeit
- Event-Delegation mit closest() für dynamische Aktionen
- UI-Auslieferung über nummerierte Chunks

## 2.4.0 – Komplett neue Oberfläche
- Neue selbstenthaltene Web-UI (Deutsch, responsive)
- Desktop-Sidebar (>900px), Bottom-Navigation auf dem Handy
- Hell-/Dunkelmodus (localStorage, Fallback prefers-color-scheme)
- 7 Tabs: Übersicht, Geräte, Zugriff, Security, FritzBox, Traffic, System
- Übersicht mit Statusbanner, Kennzahlen, Donut, Balken-Charts
- Geräte: Suche, Filter-Chips, IP-Sortierung, Sperren/Whitelist
- Zugriff: manuelles Sperren, Blockliste, Whitelist
- Security: Kacheln, Perimeter/Threat-Intel/Deep-Scan, IP-Check, Severity-Filter
- FritzBox: WAN/WLAN/Ports/Logs als lesbare Karten (JSON nur einklappbar)
- Traffic: Capture-Steuerung und tshark-Analyse
- System: Config und Status als Schlüssel/Wert
- Eigene Dialoge und Toasts statt window.confirm()
- **XSS-Fix:** alle dynamischen Werte (Hostnamen, MACs, Logs) HTML-escaped
- Ingress-BASE aus location.pathname; keine harten /api/-URLs
- Auto-Refresh 15s (sichtbarer Tab, nicht FritzBox, nicht bei Dialog/Suche); Capture 4s
- Auslieferung: ui_parts/ui_full.gz.b64/NG_POLISH entfernt – eine feste ui.html
- Barrierefreiheit: Fokus-Stile, aria-label, prefers-reduced-motion

## 2.3.4 – Update-Erkennung + Listen vertikal
## 2.3.3 – Nur aktive Geräte
## 2.3.2 – Soft errors + UI polish
## 2.3.1 – Ingress 404-Fix
