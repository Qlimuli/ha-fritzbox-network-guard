# Changelog

## 2.4.3 – FritzBox Reset (WAN + MAC-Filter)
- Neuer Endpoint `POST /api/reset/fritz`: alle WAN-Sperren aufheben + MAC-Filter erzwingen AUS
- System-Tab: roter Button **FritzBox Reset (Sperren + MAC-Filter weg)** mit Bestätigungsdialog
- Behebt Fälle, in denen Geräte (z.B. Handy) nur noch 2,4 GHz sehen, weil der MAC-Filter aktiv war
- Nach Reset: Geräte können wieder normal (auch 5 GHz) verbinden

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
