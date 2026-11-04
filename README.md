# FritzBox Network Guard – Home Assistant Add-on

Safe LAN monitoring with **learning / monitor / enforce** modes.  
WAN isolation via documented AVM TR-064 `X_AVM-DE_HostFilter1` → `DisallowWANAccessByIP`.  
Designed so you **cannot lock yourself out** of your own network.

## Safety (v2.0)

| Feature | Behavior |
|---------|----------|
| Default mode | `learning` – record baseline, notify only |
| Protected | Whitelist, HA host, gateway, Fritz, add-on IPs – **never** blocked |
| Circuit breaker | Skips auto-block if host list empty/shrinks >50%, Fritz down, or too many blocks |
| Identity | MAC-primary; re-applies block when DHCP changes IP |
| Randomized MAC | LAA bit detected – never auto-blocked |
| Dry-run | Log-only blocks |
| API | Ingress only (no host port); optional `api_token` |

## Requirements

- FRITZ!Box with TR-064 enabled (*Permit access for applications*)
- Dedicated Fritz user with **app rights only** (no remote access recommended)
- Home Assistant OS / Supervised

## Installation

1. Add this repository to the HA Add-on Store  
2. Install **FritzBox Network Guard**  
3. Configure host, user, password; leave `mode: learning` for at least `learning_days`  
4. Start → open Ingress UI  

## TR-064 actions used (AVM documented)

- `DisallowWANAccessByIP` / `GetWANAccessByIP` on `X_AVM-DE_HostFilter1`
- `GetHostNumberOfEntries` / `GetGenericHostEntry` / `X_AVM-DE_GetHostListPath` on `Hosts1`
- `GetGenericPortMappingEntry` on WAN IP/PPP connection services

## Configuration (selected)

| Option | Default | Notes |
|--------|---------|--------|
| `mode` | `learning` | `learning` / `monitor` / `enforce` |
| `learning_days` | `7` | Baseline period |
| `dry_run` | `false` | Simulate blocks |
| `max_blocks_per_cycle` | `3` | Circuit breaker |
| `fritzbox_use_https` | `true` | Port 49443 |
| `fritzbox_verify_tls` | `false` | Self-signed certs |
| `api_token` | empty | Non-Ingress API access |
| `auto_block_new_devices` | `false` | Only in `enforce` |

## Development

```bash
python3 tests/test_policy.py
python3 tests/test_state.py
```

## License

MIT
