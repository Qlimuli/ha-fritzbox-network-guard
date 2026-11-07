# Changelog

## 2.3.2 – Polish & soft errors
- Version-Anzeige überall 2.3.2
- GetDeviceLogPath 401/Invalid Action → debug (kein Warning-Spam auf FRITZ!OS 7.x)
- main.py Safety-Patches unverändert
- Ingress-Fetch-Rewrite bleibt aktiv

## 2.3.1 – Ingress 404-Fix
- Runtime-Patch: `__BASE__` + `fetch`-Rewrite für HA Ingress

## 2.3.0 – HA Update-Erkennung
- Root- und Addon-config synchron

## 2.2.9 – Runtime-Fixes
- `_insights` NameError, soft block 714/401
