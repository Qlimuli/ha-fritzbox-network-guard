#!/usr/bin/with-contenv bashio
bashio::log.info "Starting FritzBox Network Guard 2.4.0..."

export FRITZBOX_HOST=$(bashio::config 'fritzbox_host')
export FRITZBOX_USER=$(bashio::config 'fritzbox_user')
export FRITZBOX_PASSWORD=$(bashio::config 'fritzbox_password')
export SCAN_INTERVAL=$(bashio::config 'scan_interval')
export NETWORK_CIDR=$(bashio::config 'network_cidr')
export CRITICAL_MAC_PREFIXES=$(bashio::config 'critical_mac_prefixes')
export AUTO_BLOCK_NEW=$(bashio::config 'auto_block_new_devices')
export NOTIFY_ON_BLOCK=$(bashio::config 'notify_on_block')
export ENABLE_PERIMETER_SCAN=$(bashio::config 'enable_perimeter_scan')
export PERIMETER_INTERVAL=$(bashio::config 'perimeter_interval')
export ENABLE_THREAT_INTEL=$(bashio::config 'enable_threat_intel')
export THREAT_INTEL_INTERVAL=$(bashio::config 'threat_intel_interval')
export AUTO_BLOCK_THREAT_INTEL=$(bashio::config 'auto_block_threat_intel')
export DEEP_SCAN_ON_NEW=$(bashio::config 'deep_scan_on_new')
export LOG_ALERT_NOTIFY=$(bashio::config 'log_alert_notify')
export SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN}"
export DATA_DIR="/data"
mkdir -p "${DATA_DIR}"

bashio::log.info "FritzBox host: ${FRITZBOX_HOST}"
bashio::log.info "Scan interval: ${SCAN_INTERVAL}s | Network: ${NETWORK_CIDR}"
if [ -z "${FRITZBOX_PASSWORD}" ]; then
  bashio::log.warning "fritzbox_password is empty – WAN blocks / logs may fail (401)"
fi

APP_HOME="/opt/network-guard"
if [ ! -f "${APP_HOME}/main.py" ]; then
  bashio::log.error "${APP_HOME}/main.py missing"
  ls -la "${APP_HOME}" 2>/dev/null || true
  exit 1
fi

# security_engine from b64 + active-only mac_spoof patch (UI is static ui.html)
python3 - <<'PY' || true
from pathlib import Path
import base64, gzip, sys
p = Path("/opt/network-guard")

def assemble_b64(pattern, dest_name):
    chunks = sorted(p.glob(pattern))
    if not chunks:
        return False
    try:
        b64 = "".join(c.read_text().strip() for c in chunks)
        pad = (-len(b64)) % 4
        if pad:
            b64 += "=" * pad
        data = gzip.decompress(base64.b64decode(b64))
        (p / dest_name).write_bytes(data)
        print(f"Assembled {dest_name} from {len(chunks)} b64 chunks ({len(data)} bytes)", file=sys.stderr)
        return True
    except Exception as exp:
        print(f"{dest_name} b64 assemble failed: {exp}", file=sys.stderr)
        return False

assemble_b64("security_engine.b64.*", "security_engine.py")

sec = p / "security_engine.py"
if sec.exists():
    try:
        st = sec.read_text(encoding="utf-8", errors="replace")
        old_fn = """def detect_ip_mac_conflict(self, devices: list[dict]) -> list[dict]:
        by_ip: dict[str, set[str]] = {}
        for d in devices:
            ip, mac = d.get("ip"), (d.get("mac") or "").upper()
            if ip and mac:
                by_ip.setdefault(ip, set()).add(mac)"""
        new_fn = """def detect_ip_mac_conflict(self, devices: list[dict]) -> list[dict]:
        by_ip: dict[str, set[str]] = {}
        for d in devices:
            if not d.get("active"):
                continue  # offline/phantom not relevant for live attacks
            ip, mac = d.get("ip"), (d.get("mac") or "").upper()
            if ip and mac:
                by_ip.setdefault(ip, set()).add(mac)"""
        if old_fn in st:
            st = st.replace(old_fn, new_fn, 1)
            sec.write_text(st, encoding="utf-8")
            print("Patched security_engine: mac_spoof only active devices", file=sys.stderr)
        elif "offline/phantom not relevant" in st:
            print("security_engine already active-only for mac_spoof", file=sys.stderr)
        else:
            print("WARN: detect_ip_mac_conflict pattern not found", file=sys.stderr)
    except Exception as exp:
        print(f"security_engine active-only patch failed: {exp}", file=sys.stderr)

ui = p / "ui.html"
if ui.exists():
    print(f"UI file size: {ui.stat().st_size}", file=sys.stderr)
else:
    print("WARNING: ui.html missing", file=sys.stderr)
PY

if [ -f "${APP_HOME}/ui.html" ]; then
  bashio::log.info "UI ready: $(wc -c < "${APP_HOME}/ui.html") bytes"
else
  bashio::log.warning "No UI file found"
fi

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
