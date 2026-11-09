#!/usr/bin/with-contenv bashio
bashio::log.info "Starting FritzBox Network Guard 2.4.3..."

export FRITZBOX_HOST=$(bashio::config 'fritzbox_host')
export FRITZBOX_USER=$(bashio::config 'fritzbox_user')
export FRITZBOX_PASSWORD=$(bashio::config 'fritzbox_password')
export SCAN_INTERVAL=$(bashio::config 'scan_interval')
export NETWORK_CIDR=$(bashio::config 'network_cidr')
export CRITICAL_MAC_PREFIXES=$(bashio::config 'critical_mac_prefixes')
export AUTO_BLOCK_NEW=$(bashio::config 'auto_block_new_devices')
export NOTIFY_ON_BLOCK=$(bashio::config 'notify_on_block')
export ENABLE_PERIMETER_SCAN=$(bashio::config 'enable_perimeter_scan')
export PERIMETER_INTERVAL=$(bashio::config 'perimeter_interval')
export ENABLE_THREAT_INTEL=$(bashio::config 'enable_threat_intel')
export THREAT_INTEL_INTERVAL=$(bashio::config 'threat_intel_interval')
export AUTO_BLOCK_THREAT_INTEL=$(bashio::config 'auto_block_threat_intel')
export DEEP_SCAN_ON_NEW=$(bashio::config 'deep_scan_on_new')
export LOG_ALERT_NOTIFY=$(bashio::config 'log_alert_notify')
export SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN}"
export DATA_DIR="/data"
mkdir -p "${DATA_DIR}"

APP_HOME="/opt/network-guard"
if [ ! -f "${APP_HOME}/main.py" ]; then
  bashio::log.error "${APP_HOME}/main.py missing"
  exit 1
fi

python3 - <<'PY' || true
from pathlib import Path
import base64, gzip, sys

p = Path("/opt/network-guard")
ui = p / "ui.html"

# Only numbered chunks ui.html.gz.b64.00 .. (ignore broken placeholder ui.html.gz.b64)
parts = sorted(
    [x for x in p.glob("ui.html.gz.b64.[0-9]*") if x.is_file() and x.stat().st_size > 100],
    key=lambda x: x.name,
)
if parts:
    try:
        raw = "".join(x.read_text().strip() for x in parts)
        pad = (-len(raw)) % 4
        if pad:
            raw += "=" * pad
        data = gzip.decompress(base64.b64decode(raw))
        if len(data) > 5000:
            ui.write_bytes(data)
            print(f"Decoded ui.html from {len(parts)} chunk(s) ({len(data)} bytes)", file=sys.stderr)
        else:
            print(f"Decoded UI too small ({len(data)}), ignored", file=sys.stderr)
    except Exception as exp:
        print(f"ui chunk decode failed: {exp}", file=sys.stderr)
else:
    print("No UI chunks found", file=sys.stderr)

if ui.exists():
    print(f"UI file size: {ui.stat().st_size}", file=sys.stderr)
else:
    print("WARNING: ui.html missing", file=sys.stderr)

def assemble_b64(pattern, dest_name):
    chunks = sorted([c for c in p.glob(pattern) if c.stat().st_size > 0])
    if not chunks:
        return False
    try:
        b64 = "".join(c.read_text().strip() for c in chunks)
        pad = (-len(b64)) % 4
        if pad:
            b64 += "=" * pad
        data = gzip.decompress(base64.b64decode(b64))
        (p / dest_name).write_bytes(data)
        print(f"Assembled {dest_name} ({len(data)} bytes)", file=sys.stderr)
        return True
    except Exception as exp:
        print(f"{dest_name} assemble failed: {exp}", file=sys.stderr)
        return False

assemble_b64("security_engine.b64.*", "security_engine.py")
sec = p / "security_engine.py"
if sec.exists():
    try:
        st = sec.read_text(encoding="utf-8", errors="replace")
        if "offline/phantom not relevant" not in st:
            old = """def detect_ip_mac_conflict(self, devices: list[dict]) -> list[dict]:\n        by_ip: dict[str, set[str]] = {}\n        for d in devices:\n            ip, mac = d.get(\"ip\"), (d.get(\"mac\") or \"\").upper()\n            if ip and mac:\n                by_ip.setdefault(ip, set()).add(mac)"""
            new = """def detect_ip_mac_conflict(self, devices: list[dict]) -> list[dict]:\n        by_ip: dict[str, set[str]] = {}\n        for d in devices:\n            if not d.get(\"active\"):\n                continue  # offline/phantom not relevant for live attacks\n            ip, mac = d.get(\"ip\"), (d.get(\"mac\") or \"\").upper()\n            if ip and mac:\n                by_ip.setdefault(ip, set()).add(mac)"""
            if old in st:
                sec.write_text(st.replace(old, new, 1), encoding="utf-8")
                print("Patched security_engine active-only", file=sys.stderr)
    except Exception as exp:
        print(f"security patch failed: {exp}", file=sys.stderr)
PY

# Inject FritzBox-Reset button into System panel (if not already present)
if [ -f "${APP_HOME}/ui.html" ] && ! grep -q 'id="cfg-reset-fritz"' "${APP_HOME}/ui.html" 2>/dev/null; then
  python3 - <<'UIPY' || true
from pathlib import Path
ui = Path("/opt/network-guard/ui.html")
html = ui.read_text(encoding="utf-8", errors="replace")
if 'id="cfg-reset-fritz"' in html:
    print("Reset button already present", flush=True)
else:
    btn_html = (
        '            <button type="button" class="btn btn-danger" id="cfg-reset-fritz" style="margin-top:.5rem">'
        'FritzBox Reset (Sperren + MAC-Filter weg)</button>\n'
        '            <p class="muted" style="font-size:.75rem;margin-top:.35rem">'
        'Hebt alle WAN-Sperren auf und schaltet den MAC-Filter aus. '
        'Nützlich wenn Geräte (z.B. Handy) nur noch 2,4 GHz sehen.</p>\n'
    )
    marker = (
        '<button type="button" class="btn ghost" id="cfg-threat">Threat-Intel</button>\n'
        '          </div>\n'
        '        </div>'
    )
    if marker in html:
        html = html.replace(
            marker,
            '<button type="button" class="btn ghost" id="cfg-threat">Threat-Intel</button>\n'
            '          </div>\n'
            + btn_html
            + '        </div>',
            1,
        )
        print("Injected reset button HTML", flush=True)
    else:
        print("Marker for reset button not found", flush=True)

    js = (
        '\n$("#cfg-reset-fritz")?.addEventListener("click",async()=>{\n'
        '  if(!(await confirmDlg("FritzBox Reset","Alle WAN-Sperren aufheben und MAC-Filter deaktivieren? '
        'Geräte können danach wieder normal (auch 5 GHz) verbinden.","Reset ausführen"))) return;\n'
        '  toast("Reset läuft…");\n'
        '  try{\n'
        '    const r=await api("/api/reset/fritz",{method:"POST",body:{}});\n'
        '    toast(r.message||"Reset fertig");\n'
        '    refreshConfig(); refreshBlocked(); refreshDevices();\n'
        '  }catch(e){toast("Reset: "+e.message);}\n'
        '});\n'
    )
    target = '$("#cfg-threat")?.addEventListener("click",()=>$("#sec-threat")?.click());'
    if target in html:
        html = html.replace(target, target + js, 1)
        print("Injected reset button JS", flush=True)
    else:
        html = html.replace("</script>", js + "\n</script>", 1)
        print("Injected reset JS at end of script", flush=True)
    ui.write_text(html, encoding="utf-8")
    print(f"UI updated, size={ui.stat().st_size}", flush=True)
UIPY
fi

if [ -f "${APP_HOME}/ui.html" ]; then
  bashio::log.info "UI ready: $(wc -c < "${APP_HOME}/ui.html") bytes"
else
  bashio::log.warning "No UI file found"
fi

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
