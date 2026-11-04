# FritzBox Network Guard – Dokumentation

## Überblick

Das Add-on überwacht das LAN, bewertet Geräte mit einem transparenten Risiko-Score und kann den **Internetzugang (WAN)** einzelner Geräte über die FritzBox sperren. Die LAN-Kommunikation bleibt möglich.

**Standardmodus ist `learning`:** Es wird nur gelernt und benachrichtigt, nicht automatisch gesperrt.

## Modi

| Modus | Auto-Sperre | Manuelle Sperre |
|-------|-------------|-----------------|
| `learning` | nein (Baseline) | ja (außer geschützte Geräte) |
| `monitor` | nein | ja |
| `enforce` | ja (Regeln + Schwellwerte) | ja |

## Schutz vor Selbst-Aussperrung

Niemals gesperrt werden: Whitelist, HA-Host, Gateway, FritzBox-Adresse.

**Schutzschalter**, wenn die Geräteliste leer ist, stark schrumpft, die FritzBox unerreichbar ist oder mehr als `max_blocks_per_cycle` Sperren anstehen.

Zufällige/Privacy-MACs (LAA-Bit) werden **nicht** auto-gesperrt.

## FritzBox-Benutzer

Eigener Benutzer nur mit **Berechtigung für Anwendungen**, ohne Fernzugriff. Bei Auth-Fehlern: exponentielles Backoff.

## TLS

- `fritzbox_use_https: true` → Port **49443**
- `fritzbox_verify_tls: false` Standard (selbstsigniert)

## API

Nur über **Ingress**. Optional `api_token`. CSRF für UI-Mutationen (`GET /api/csrf`).

## Daten

- `/data/state.json` – atomar
- `/data/audit.jsonl` – Audit mit Rotation
- Start: Abgleich mit `GetWANAccessByIP`
