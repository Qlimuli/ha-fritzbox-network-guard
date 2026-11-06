# Changelog

## 2.2.8 – Boot-Load Fix & robuste UI
- Sofort-Refresh + Retries (50ms / 1.5s / 4s) damit Overview nicht auf „Verbinde…“ hängen bleibt
- Vollständige `ui_full.gz.b64` (Single-File) wiederhergestellt und verifiziert
- Chunks neu geschrieben und Assembly getestet
- Dockerfile LABEL auf 2.2.8, Config-Version 2.2.8
- SID-Login Logging bereinigt

## 2.2.7 – UI-Assembly & Laden-Fix
- Vollständige `ui_full.gz.b64` (Single-File) wiederhergestellt
- Fallback-`ui.html` aktualisiert
- run.sh: Single-File nur bei >5 KB nutzen (verhindert kaputte Truncates)
- Sofort-Status in der GUI: „Verbinde…“ + Base-Pfad sichtbar

## 2.2.6 – GUI bleibt nicht mehr auf „Laden…“
- Ingress-Base-Pfad (`__BASE__`)
- API-Timeout 12s, soft Overview-Load
- Fehler im Header statt ewig „Laden…“

## 2.2.5 – Ingress API-Pfade
## 2.2.4 – Full GUI fix
## 2.2.0 – Packet Capture
## 2.0.0 – Safety rewrite
