# Changelog

## 1.5.5
- Only actively connected devices are auto-blocked / threat-detected (inactive Fritz history entries are ignored for blocking and MAC-conflict checks). Offline devices cannot pose an active threat.

## 1.3.1
- Repository structure fixed for Home Assistant Add-on Store (addon in subdirectory)
- Version bump so Supervisor detects the update

## 1.3.0
- SecurityEngine: perimeter port scan of public IP
- Threat intelligence (FireHOL level1, Spamhaus DROP/EDROP)
- MAC conflict / spoofing heuristics
- IDS webhook endpoint for Suricata / Wazuh / Zeek
- API: /api/security/*

## 1.2.0
- MAC quarantine / dynamic filter
- Mobile-optimized UI

## 1.0.0
- Initial release: LAN scan, FritzBox WAN block, Web UI
