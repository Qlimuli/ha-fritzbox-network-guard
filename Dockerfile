# Home Assistant App – FritzBox Network Guard
FROM ghcr.io/home-assistant/base:3.21

ENV LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1

RUN apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    libpcap

RUN pip3 install --no-cache-dir \
    fritzconnection \
    flask \
    waitress \
    requests

COPY rootfs/ /

RUN chmod a+x /run.sh

WORKDIR /app

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Network scanner + FritzBox IP blacklist / isolation" \
    io.hass.type="addon" \
    io.hass.version="1.2.0" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
