#!/usr/bin/with-contenv bashio
# ==============================================================================
# FritzBox Network Guard add-on
# ==============================================================================

bashio::log.info "Starting FritzBox Network Guard..."

# Export options as environment variables for the Python app
export FRITZBOX_HOST=$(bashio::config 'fritzbox_host')
export FRITZBOX_USER=$(bashio::config 'fritzbox_user')
export FRITZBOX_PASSWORD=$(bashio::config 'fritzbox_password')
export SCAN_INTERVAL=$(bashio::config 'scan_interval')
export NETWORK_CIDR=$(bashio::config 'network_cidr')
export CRITICAL_MAC_PREFIXES=$(bashio::config 'critical_mac_prefixes')
export AUTO_BLOCK_NEW=$(bashio::config 'auto_block_new_devices')
export NOTIFY_ON_BLOCK=$(bashio::config 'notify_on_block')
export SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN}"

# Persistent data
export DATA_DIR="/data"
mkdir -p "${DATA_DIR}"

bashio::log.info "FritzBox host: ${FRITZBOX_HOST}"
bashio::log.info "Scan interval: ${SCAN_INTERVAL}s"
bashio::log.info "Network: ${NETWORK_CIDR}"

exec python3 /app/main.py
