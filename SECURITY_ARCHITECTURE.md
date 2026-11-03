# Security Architecture – FritzBox Network Guard

## Ziel

Intelligente Abwehr auf mehreren Ebenen, **realistisch** im Home-Assistant-Add-on
(mit `host_network: true`) und klarer Trennung zu schweren Open-Source-Sensoren.

## Was dieses Add-on **selbst** macht

| Anforderung | Umsetzung |
|-------------|-----------|
| Asset Discovery (LAN) | nmap + FritzBox Hosts API |
| Neue / kritische Geräte | Auto-Block + MAC-Quarantäne |
| MAC-Konflikt / Spoofing-Heuristik | IP mit mehreren MACs im gleichen Scan |
| MAC–IP-Historie | Wechsel der Bindung → Event |
| Perimeter Port-Scan | nmap der **öffentlichen IP** auf riskante Ports |
| Threat Intelligence | FireHOL level1 + Spamhaus DROP/EDROP |
| Reputations-Blocking | Match → FritzBox WAN-Sperre + HA-Notify |
| IDS-Anbindung | `POST /api/security/webhook` (Suricata/Wazuh/Zeek) |
| Event-Log | `/api/security/events` + Persistenz |

## Was **nicht** im Add-on laufen sollte (zu schwer / falsche Schicht)

| Anforderung | Empfohlenes externes Tool |
|-------------|---------------------------|
| NIDS / DPI / Exploit-Signaturen | **Suricata** (oder Snort) auf Router/Spiegelport/Proxmox |
| Protokoll-Anomalien, Lateral Movement | **Zeek** |
| DDoS volumetrisch | ISP / Cloudflare / Router-Firewall – nicht HA |
| Host FIM, Log-SIEM, Privilege Escalation | **Wazuh** (Agent auf Servern) |
| Vollständiger Vuln-Scan | **OpenVAS / Greenbone** (separater Host) |
| Rogue AP | Dedicated WiFi-Monitor (Kismet) – braucht Monitor-Mode |

## Integrationspfad (SOAR-light)

```
Suricata/Wazuh  --JSON webhook-->  Network Guard /api/security/webhook
                                         |
                                         +--> Event + HA Notification
                                         +--> FritzBox DisallowWANAccessByIP
                                         +--> optional MAC-Filter quarantine
```

Beispiel Suricata (eve → curl):

```bash
curl -X POST http://homeassistant:8099/api/security/webhook \
  -H 'Content-Type: application/json' \
  -d '{"src_ip":"1.2.3.4","signature":"ET SCAN Nmap","severity":"1","sensor":"suricata"}'
```

## API

| Method | Path | Zweck |
|--------|------|--------|
| GET | `/api/security` | Status (Perimeter, Intel, Stats) |
| GET | `/api/security/events` | Letzte Security-Events |
| POST | `/api/security/perimeter` | Perimeter-Scan jetzt |
| POST | `/api/security/threat-intel` | Blocklisten neu laden |
| POST | `/api/security/check-ip` | `{"ip":"…"}` gegen Intel prüfen |
| POST | `/api/security/webhook` | Externe IDS-Alerts |

## Schichtenmodell

```
┌─────────────────────────────────────────────────────────┐
│ 4  Host: Wazuh agents (FIM, processes, auth logs)       │
├─────────────────────────────────────────────────────────┤
│ 3  Traffic: Suricata/Zeek (DPI, signatures, NetFlow)    │
├─────────────────────────────────────────────────────────┤
│ 2  LAN: Network Guard (discovery, MAC, auto-isolate)    │
├─────────────────────────────────────────────────────────┤
│ 1  Perimeter: WAN port scan + Threat Intel blocklists   │
├─────────────────────────────────────────────────────────┤
│ 0  Enforcement: FritzBox HostFilter + optional MAC ACL  │
└─────────────────────────────────────────────────────────┘
```

## Empfehlung zum Ausrollen

1. Network Guard Add-on (dieses Repo) – LAN + Perimeter + Intel
2. Suricata auf einem Linux-Host mit Port-Mirror oder als LXC
3. Wazuh Manager + Agents auf NAS/Servern
4. Webhooks → Network Guard für einheitliche Isolation über FritzBox
