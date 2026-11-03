#!/usr/bin/with-contenv bashio
# ==============================================================================
# FritzBox Network Guard add-on
# ==============================================================================

bashio::log.info "Starting FritzBox Network Guard 1.4.0..."

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
export SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN}"

export DATA_DIR="/data"
mkdir -p "${DATA_DIR}"

bashio::log.info "FritzBox host: ${FRITZBOX_HOST}"
bashio::log.info "Scan interval: ${SCAN_INTERVAL}s"
bashio::log.info "Network: ${NETWORK_CIDR}"
bashio::log.info "Perimeter: ${ENABLE_PERIMETER_SCAN} every ${PERIMETER_INTERVAL}s"
bashio::log.info "Threat-Intel: ${ENABLE_THREAT_INTEL} every ${THREAT_INTEL_INTERVAL}s"

APP_HOME="/opt/network-guard"
if [ ! -f "${APP_HOME}/main.py" ]; then
  bashio::log.error "${APP_HOME}/main.py missing – image build incomplete"
  ls -la "${APP_HOME}" /app 2>/dev/null || true
  exit 1
fi

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
