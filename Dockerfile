# Home Assistant App – FritzBox Network Guard
# Modern Dockerfile (no BUILD_FROM dependency – Supervisor 2026.04+)

FROM ghcr.io/home-assistant/base:3.21

ENV LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1

# System packages: Python, nmap for scanning
RUN apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    libpcap

# Python dependencies (only what the app actually uses)
RUN pip3 install --no-cache-dir \
    fritzconnection \
    flask \
    flask-cors \
    requests

# Application files
COPY rootfs/ /

RUN chmod a+x /run.sh

WORKDIR /app

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Network scanner + FritzBox IP blacklist / isolation" \
    io.hass.type="addon" \
    io.hass.version="1.0.1" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
