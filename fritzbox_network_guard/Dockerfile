ARG BUILD_FROM=ghcr.io/home-assistant/base:3.21
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_HOME=/opt/network-guard

RUN apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    libpcap \
    curl

RUN pip3 install --no-cache-dir \
    fritzconnection \
    flask \
    waitress \
    requests

COPY rootfs/run.sh /run.sh
COPY rootfs/app/ ${APP_HOME}/

RUN chmod a+x /run.sh \
    && test -f ${APP_HOME}/main.py \
    && test -f ${APP_HOME}/main_full.b64.00 \
    && ls -la ${APP_HOME}/ | head -40

WORKDIR ${APP_HOME}

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Safe LAN monitor + FritzBox WAN isolation" \
    io.hass.type="addon" \
    io.hass.version="2.0.1" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
