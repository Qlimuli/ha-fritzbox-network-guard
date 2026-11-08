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
    curl \
    tcpdump \
    tshark \
    wireshark-common

RUN pip3 install --no-cache-dir \
    fritzconnection \
    flask \
    waitress \
    requests

COPY rootfs/run.sh /run.sh
COPY rootfs/app/ ${APP_HOME}/

RUN chmod a+x /run.sh \
    && test -f ${APP_HOME}/main.py \
    && test -f ${APP_HOME}/packet_capture.py \
    && test -f ${APP_HOME}/fritz_insights.py \
    && python3 -m py_compile ${APP_HOME}/packet_capture.py \
    && python3 -m py_compile ${APP_HOME}/fritz_insights.py \
    && ls -la ${APP_HOME}/ | head -50

WORKDIR ${APP_HOME}

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="LAN monitor, Fritz packet capture (Wireshark-compatible), traffic analysis, WAN isolation" \
    io.hass.type="addon" \
    io.hass.version="2.4.1" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
