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

# Always assemble security_engine from b64 chunks (local or download from GitHub tip)
RUN python3 - <<'PY'
from pathlib import Path
import base64, gzip, urllib.request, sys
p = Path("/opt/network-guard")
chunks = sorted(p.glob("security_engine.b64.*"))
if not chunks or all(c.stat().st_size < 10 for c in chunks):
    base = "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/main/fritzbox_network_guard/rootfs/app/"
    parts = []
    for i in range(4):
        try:
            with urllib.request.urlopen(base + f"security_engine.b64.{i:02d}", timeout=30) as r:
                parts.append(r.read().decode().strip())
        except Exception as e:
            print("download se chunk", i, e, file=sys.stderr)
            parts = []
            break
    if parts:
        data = gzip.decompress(base64.b64decode("".join(parts)))
        (p / "security_engine.py").write_bytes(data)
        print("Downloaded+assembled security_engine.py", len(data), file=sys.stderr)
elif chunks:
    b64 = "".join(c.read_text().strip() for c in chunks)
    data = gzip.decompress(base64.b64decode(b64))
    (p / "security_engine.py").write_bytes(data)
    print("Assembled security_engine.py from local chunks", len(data), file=sys.stderr)
# Fail build if still broken / stub-only
se = (p / "security_engine.py").read_text()
if se.strip() in ("test", "") or "class SecurityEngine" not in se:
    raise SystemExit("security_engine.py invalid after assemble")
if len(se) < 5000 or "Perimeter" not in se:
    raise SystemExit("security_engine.py looks like stub – assemble from chunks failed")
print("security_engine.py OK", len(se), "bytes", file=sys.stderr)
PY

RUN chmod a+x /run.sh \
    && test -f ${APP_HOME}/main.py \
    && ls -la ${APP_HOME}/

WORKDIR ${APP_HOME}

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Network scanner + FritzBox isolation + SecurityEngine" \
    io.hass.type="addon" \
    io.hass.version="1.5.4" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
