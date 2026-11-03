ARG BUILD_FROM=ghcr.io/home-assistant/base:3.19
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8

# Install Python and required packages
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-nacl \
    nmap \
    && pip3 install --break-system-packages --no-cache-dir \
        fritzconnection \
        flask \
        flask-cors \
        requests \
        scapy \
        netaddr

WORKDIR /app

# Copy application
COPY rootfs/ /

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Network scanner + FritzBox IP blacklist / isolation" \
    io.hass.type="addon" \
    io.hass.version="1.0.0"
