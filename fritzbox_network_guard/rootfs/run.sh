#!/usr/bin/with-contenv bashio
# FritzBox Network Guard 2.0.0
bashio::log.info "Starting FritzBox Network Guard 2.0.0..."

export FRITZBOX_HOST=$(bashio::config 'fritzbox_host')
export FRITZBOX_USER=$(bashio::config 'fritzbox_user')
export FRITZBOX_PASSWORD=$(bashio::config 'fritzbox_password')
export FRITZBOX_USE_HTTPS=$(bashio::config 'fritzbox_use_https')
export FRITZBOX_VERIFY_TLS=$(bashio::config 'fritzbox_verify_tls')
export MODE=$(bashio::config 'mode')
export LEARNING_DAYS=$(bashio::config 'learning_days')
export SCAN_INTERVAL=$(bashio::config 'scan_interval')
export NETWORK_CIDR=$(bashio::config 'network_cidr')
export FULL_SCAN_INTERVAL_HOURS=$(bashio::config 'full_scan_interval_hours')
export CRITICAL_MAC_PREFIXES=$(bashio::config 'critical_mac_prefixes')
export AUTO_BLOCK_NEW=$(bashio::config 'auto_block_new_devices')
export WHITELIST_MACS=$(bashio::config 'whitelist_macs')
export WHITELIST_IPS=$(bashio::config 'whitelist_ips')
export MAX_BLOCKS_PER_CYCLE=$(bashio::config 'max_blocks_per_cycle')
export DRY_RUN=$(bashio::config 'dry_run')
export NOTIFY_ON_BLOCK=$(bashio::config 'notify_on_block')
export NOTIFY_THRESHOLD=$(bashio::config 'notify_threshold')
export BLOCK_THRESHOLD=$(bashio::config 'block_threshold')
export NOTIFY_SERVICE=$(bashio::config 'notify_service')
export API_TOKEN=$(bashio::config 'api_token')
export ENABLE_METRICS=$(bashio::config 'enable_metrics')
export INGRESS_ONLY=true
export SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN}"
export DATA_DIR="/data"
mkdir -p "${DATA_DIR}"

bashio::log.info "Mode: ${MODE} | FritzBox: ${FRITZBOX_HOST} | HTTPS: ${FRITZBOX_USE_HTTPS}"
bashio::log.info "Scan interval: ${SCAN_INTERVAL}s | Network: ${NETWORK_CIDR} | Dry-run: ${DRY_RUN}"
if [ -z "${FRITZBOX_PASSWORD}" ]; then
  bashio::log.warning "fritzbox_password is empty – TR-064 calls will fail"
fi
bashio::log.info "Use a dedicated FritzBox user with app rights only (no remote access)."

APP_HOME="/opt/network-guard"
if [ ! -f "${APP_HOME}/main.py" ]; then
  bashio::log.error "${APP_HOME}/main.py missing"
  ls -la "${APP_HOME}" 2>/dev/null || true
  exit 1
fi

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
