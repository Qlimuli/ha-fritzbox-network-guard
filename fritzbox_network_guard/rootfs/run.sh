#!/usr/bin/with-contenv bashio
bashio::log.info "Starting FritzBox Network Guard 2.2.9..."

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

ok = False
# Prefer complete ui_parts first (>=30KB) – most reliable
parts = sorted(p.glob("ui_parts/*.html"))
parts_data = b"".join(x.read_bytes() for x in parts) if parts else b""
if len(parts_data) >= 30000:
    (p / "ui.html").write_bytes(parts_data)
    print(f"Assembled ui.html from {len(parts)} parts ({len(parts_data)} bytes)", file=sys.stderr)
    ok = True
if not ok:
    single = p / "ui_full.gz.b64"
    if single.exists() and single.stat().st_size > 5000:
        try:
            b64 = single.read_text().strip()
            pad = (-len(b64)) % 4
            if pad:
                b64 += "=" * pad
            data = gzip.decompress(base64.b64decode(b64))
            (p / "ui.html").write_bytes(data)
            print(f"Assembled ui.html from single ui_full.gz.b64 ({len(data)} bytes)", file=sys.stderr)
            ok = True
        except Exception as exp:
            print(f"single ui_full.gz.b64 failed: {exp}", file=sys.stderr)
if not ok:
    ok = assemble_b64("ui_full.gz.b64.*", "ui.html")
if not ok and parts and len(parts_data) > 10000:
    (p / "ui.html").write_bytes(parts_data)
    print(f"Assembled ui.html from {len(parts)} parts fallback ({len(parts_data)} bytes)", file=sys.stderr)
elif not ok:
    print("Using existing ui.html", file=sys.stderr)
ui = p / "ui.html"
if ui.exists():
    sz = ui.stat().st_size
    print(f"UI file size: {sz}", file=sys.stderr)
    if sz < 10000:
        print("WARNING: ui.html suspiciously small", file=sys.stderr)

assemble_b64("security_engine.b64.*", "security_engine.py")
PY

if [ -f "${APP_HOME}/ui.html" ]; then
  bashio::log.info "UI ready: $(wc -c < "${APP_HOME}/ui.html") bytes"
else
  bashio::log.warning "No UI file found"
fi

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
