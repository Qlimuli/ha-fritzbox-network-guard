ARG BUILD_FROM=ghcr.io/home-assistant/base:3.21
FROM ${BUILD_FROM}

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

RUN mkdir -p /app

# Copy application files explicitly (HA build sometimes skips nested dirs)
COPY rootfs/run.sh /run.sh
COPY rootfs/main.py /app/main.py
COPY rootfs/mac_guard.py /app/mac_guard.py
COPY rootfs/security_engine.py /app/security_engine.py
COPY rootfs/ui.html /app/ui.html
# Keep nested path too if present in build context
COPY rootfs/app/ /app/

RUN chmod a+x /run.sh \
    && test -f /app/main.py \
    && ls -la /app/

WORKDIR /app

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Network scanner + FritzBox IP blacklist / isolation + SecurityEngine" \
    io.hass.type="addon" \
    io.hass.version="1.3.3" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
