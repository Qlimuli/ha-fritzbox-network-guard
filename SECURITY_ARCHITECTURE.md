# Security Architecture – FritzBox Network Guard 2.0

## Goals

1. Never lock the operator out of their own network  
2. Prefer visibility (learning/monitor) over automatic enforcement  
3. Use only AVM-documented TR-064 actions for enforcement  

## Enforcement

```
X_AVM-DE_HostFilter1 → DisallowWANAccessByIP (NewIPv4Address, NewDisallow)
X_AVM-DE_HostFilter1 → GetWANAccessByIP   (reconcile)
```

WAN-only isolation. LAN remains reachable.

## Safety controls

- Modes: learning → monitor → enforce  
- Hard deny list for blocks (whitelist, host, gateway, Fritz)  
- Circuit breaker on bad host-list / Fritz outage / burst blocks  
- MAC identity + DHCP rebind  
- Randomized MAC (LAA) never auto-blocked  
- Dry-run, audit log, Ingress-only API  

## What stays out of the add-on

Suricata/Zeek DPI, volumetric DDoS, host FIM – integrate via events/webhooks if needed.
