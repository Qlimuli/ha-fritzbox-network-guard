# Changelog

## 2.0.0 – Safety & Visibility rewrite
- Modes: `learning` | `monitor` | `enforce` (default **learning**)
- Hard protected devices (whitelist, HA host, gateway, Fritz, local IPs) – never blocked
- Circuit breaker: empty/shrunk host list, Fritz down, max blocks per cycle
- Identity by MAC; DHCP rebind re-applies WAN block; randomized/LAA MACs never auto-blocked
- Atomic `/data/state.json`, append-only `/data/audit.jsonl`, startup reconcile via `GetWANAccessByIP`
- Fritz client: HTTPS:49443 option, auth backoff, session reuse
- API: Ingress-only (no host port), optional `api_token`, CSRF, input validation, security headers
- Risk score with factors; device inventory; router port-mapping view; HA sensors/events
- Plain Python modules (no obfuscated payload for core logic)
- pytest coverage for policy and state

## 1.5.5
- Only actively connected devices auto-blocked / threat-detected

## 1.5.4
- Interface labels, event cooldown

## 1.3.0
- SecurityEngine perimeter / threat intel (optional, off by default in 2.0)
