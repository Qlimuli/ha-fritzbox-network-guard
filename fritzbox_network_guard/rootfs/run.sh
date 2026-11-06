#!/usr/bin/with-contenv bashio
bashio::log.info "Starting FritzBox Network Guard 2.2.4..."

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

# Prefer the complete bundled ui.html (v2.2.4+). Only assemble from ui_parts
# if the main file is missing or suspiciously small (broken previous assembly).
UI_FILE="${APP_HOME}/ui.html"
if [ -f "${UI_FILE}" ] && [ "$(wc -c < "${UI_FILE}")" -gt 15000 ]; then
  bashio::log.info "Using complete ui.html ($(wc -c < "${UI_FILE}") bytes)"
elif ls "${APP_HOME}/ui_parts"/*.html >/dev/null 2>&1; then
  cat $(ls "${APP_HOME}/ui_parts"/*.html | sort) > "${UI_FILE}"
  bashio::log.info "Assembled UI from ui_parts ($(wc -c < "${UI_FILE}") bytes)"
else
  bashio::log.warning "No usable UI found – pages may be empty"
fi

python3 - <<'PY' || true
from pathlib import Path
import base64, gzip, sys
p = Path("/opt/network-guard")

def assemble(pattern, dest_name):
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
        print(f"Assembled {dest_name} from {len(chunks)} chunks ({len(data)} bytes)", file=sys.stderr)
        return True
    except Exception as exp:
        print(f"{dest_name} assemble failed: {exp}", file=sys.stderr)
        return False

ui = p / "ui.html"
if not ui.exists() or ui.stat().st_size < 5000:
    assemble("ui_full.gz.b64.*", "ui.html") or assemble("ui.b64.*", "ui.html")

assemble("security_engine.b64.*", "security_engine.py")
PY

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
