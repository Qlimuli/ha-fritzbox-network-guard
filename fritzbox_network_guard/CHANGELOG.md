# Changelog

## 2.4.4 – MAC-Filter nie mehr automatisch aktivieren (Lockout-Fix)
- **Kritisch:** MAC-Filter (WLAN-Zugang beschränken) wird vom Add-on **nie mehr eingeschaltet**
- Ursache für „FritzBox-GUI nicht erreichbar“ / „nur noch 2,4 GHz“: MAC-Filter + randomisierte Handy-MACs
- `MacQuarantine.apply()` schaltet den Filter nur noch **aus**, nie ein
- Beim Add-on-Start: MAC-Filter wird forciert deaktiviert (Sicherheitsnetz)
- Isolation bleibt über WAN-Sperre (`DisallowWANAccessByIP`) – blockiert nur Internet, nicht die lokale Fritz-GUI
- Reset-Button (System-Tab) bleibt und hebt alle WAN-Sperren + MAC-Filter auf

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
