# FritzBox Network Guard – Documentation

## Overview

This add-on continuously scans the configured local network and reacts to security-relevant events by placing the offending IP on the FritzBox parental-control / HostFilter blacklist. The device loses WAN (internet) access while remaining reachable inside the LAN for further investigation.

## Blocking mechanism

The add-on calls the TR-064 service exposed by modern Fritz!OS:

```
Service : X_AVM-DE_HostFilter1
Action  : DisallowWANAccessByIP
Arguments:
  NewIPv4Address = <ip>
  NewDisallow    = true | false
```

This is the same mechanism that the FritzBox web interface uses under  
**Internet → Filters → Parental Controls → Device Block**.

## Web UI

Available via Home Assistant Ingress (side panel) or directly on port 8099.

- List of currently blocked devices
- One-click unblock
- Manual IP block
- Overview of last-seen devices from the scanner

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/blocked` | JSON list of blocked devices |
| GET | `/api/known` | JSON list of known devices |
| POST | `/api/block` | Body `{"ip":"…","reason":"…"}` |
| POST | `/api/unblock` | Body `{"ip":"…"}` |
| GET | `/api/status` | Current configuration summary |

## Tips

- Start with `auto_block_new_devices: false` and only enable it after you have a stable known-device baseline.
- Critical infrastructure (HA host, your main PC, NAS) should never be auto-blocked.
- You can combine the add-on with Home Assistant device_tracker entities for richer logic via automations.
