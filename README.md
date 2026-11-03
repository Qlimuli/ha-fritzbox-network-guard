# FritzBox Network Guard – Home Assistant Add-on

Scans the local network for critical / suspicious devices.  
On a security alert the IP is added to the **FritzBox blacklist** (WAN access is blocked via `X_AVM-DE_HostFilter`).  
Blocked devices can be **unlocked again** in the add-on GUI.

## Features

- Periodic network scan (nmap)
- Auto-block of **new unknown devices** (configurable)
- Block by **critical MAC prefixes** (e.g. known IoT / camera OUIs)
- FritzBox integration via TR-064 (`DisallowWANAccessByIP`)
- Clean dark Web UI (Ingress) to list & unblock devices
- Optional Home Assistant persistent notifications
- Manual block / unblock

## Requirements

- AVM FRITZ!Box with TR-064 enabled  
  (*Permit access for applications* must be on)
- User account on the FritzBox with sufficient rights
- Home Assistant OS / Supervised (for add-on support)

## Installation

1. Add this repository to the Home Assistant Add-on Store  
   (or clone / copy the folder into `/addons`)
2. Install **FritzBox Network Guard**
3. Configure:
   - FritzBox host (usually `fritz.box` or `192.168.178.1`)
   - Username & password
   - Network CIDR (e.g. `192.168.178.0/24`)
   - Scan interval
   - Optional: comma-separated critical MAC prefixes (`AA:BB:CC,DD:EE:FF`)
4. Start the add-on
5. Open the Web UI via the side panel or Ingress

## How isolation works

The add-on uses the official TR-064 action:

```text
X_AVM-DE_HostFilter1 → DisallowWANAccessByIP
```

This **blocks internet (WAN) access** for the device while it can still communicate inside the LAN.  
Full Layer-2 isolation is not exposed by the standard FritzBox API; WAN blocking is the supported and reliable method.

## Unblocking

In the add-on UI simply click **Entsperren** next to any blocked device.  
The same action can be triggered via the REST API:

```bash
curl -X POST http://<addon>:8099/api/unblock -d '{"ip":"192.168.178.50"}'
```

## Configuration options

| Option | Description | Default |
|--------|-------------|---------|
| `fritzbox_host` | Hostname / IP of the FritzBox | `fritz.box` |
| `fritzbox_user` | FritzBox user | – |
| `fritzbox_password` | Password | – |
| `scan_interval` | Seconds between scans | `60` |
| `network_cidr` | Network to scan | `192.168.178.0/24` |
| `critical_mac_prefixes` | Comma-separated OUI prefixes that trigger a block | empty |
| `auto_block_new_devices` | Automatically block devices never seen before | `true` |
| `notify_on_block` | Create HA persistent notification | `true` |

## Disclaimer

Use at your own risk. Always whitelist critical devices (Home Assistant, your own clients) if you enable auto-block of new devices.

## License

MIT
