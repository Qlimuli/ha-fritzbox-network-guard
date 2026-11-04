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

# Assemble main_app.py from main_gz.* if needed; keep plain modules as-is
RUN python3 - <<'PY'
from pathlib import Path
import base64, gzip, sys
p = Path("/opt/network-guard")
app = p / "main_app.py"
if not app.exists() or app.stat().st_size < 1000:
    chunks = sorted(p.glob("main_gz.*"))
    if not chunks:
        # fall back: main.py might already be the full app
        main = p / "main.py"
        if main.exists() and main.stat().st_size > 5000 and b"Flask" in main.read_bytes():
            print("main.py already full app", main.stat().st_size)
            sys.exit(0)
        raise SystemExit("missing main_app.py and main_gz.* chunks")
    data = gzip.decompress(base64.b64decode("".join(c.read_text().strip() for c in chunks)))
    app.write_bytes(data)
    print("assembled main_app.py", len(data))
# Ensure entrypoint main.py bootstraps main_app
boot = p / "main.py"
content = boot.read_text() if boot.exists() else ""
if "main_app" not in content and (p / "main_app.py").exists():
    boot.write_text(
        "#!/usr/bin/env python3\n"
        "import runpy\n"
        "from pathlib import Path\n"
        "runpy.run_path(str(Path(__file__).resolve().parent / 'main_app.py'), run_name='__main__')\n"
    )
    print("wrote bootstrap main.py")
required = ["main.py", "policy.py", "risk.py", "state.py", "fritz_client.py", "discovery.py", "ha_integration.py"]
missing = [r for r in required if not (p / r).exists()]
if missing:
    raise SystemExit(f"missing modules: {missing}")
print("modules OK", sorted(x.name for x in p.glob('*.py')))
PY

RUN chmod a+x /run.sh && ls -la ${APP_HOME}/

WORKDIR ${APP_HOME}

CMD [ "/run.sh" ]

LABEL \
    io.hass.name="FritzBox Network Guard" \
    io.hass.description="Safe LAN monitor + FritzBox WAN isolation" \
    io.hass.type="addon" \
    io.hass.version="2.0.1" \
    org.opencontainers.image.source="https://github.com/Qlimuli/ha-fritzbox-network-guard"
