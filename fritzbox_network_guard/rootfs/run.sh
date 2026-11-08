#!/usr/bin/with-contenv bashio
bashio::log.info "Starting FritzBox Network Guard 2.4.1..."

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
import base64, gzip, sys, urllib.request

p = Path("/opt/network-guard")
ui = p / "ui.html"

parts = sorted([x for x in p.glob("ui.html.gz.b64*") if x.is_file() and x.stat().st_size > 0], key=lambda x: x.name)
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
    except Exception as exp:
        print(f"ui chunk decode failed: {exp}", file=sys.stderr)

if (not ui.exists()) or ui.stat().st_size < 5000:
    urls = [
        "https://raw.githubusercontent.com/Qlimuli/ha-fritzbox-network-guard/4fa1a8c5c0d55126c13ffeabd1b9f603ce2d8566/fritzbox_network_guard/rootfs/app/ui.html",
        "https://cdn.jsdelivr.net/gh/Qlimuli/ha-fritzbox-network-guard@4fa1a8c5c0d55126c13ffeabd1b9f603ce2d8566/fritzbox_network_guard/rootfs/app/ui.html",
    ]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=20) as r:
                data = r.read()
            if len(data) > 5000:
                ui.write_bytes(data)
                print(f"Restored ui.html from GitHub ({len(data)} bytes)", file=sys.stderr)
                break
        except Exception as exp:
            print(f"UI restore failed: {exp}", file=sys.stderr)

if ui.exists() and ui.stat().st_size > 5000:
    try:
        html = ui.read_text(encoding="utf-8", errors="replace")
        changed = False
        if '.replace(/&/g,"&")' in html:
            html = html.replace(
                '.replace(/&/g,"&").replace(/</g,"<").replace(/>/g,">").replace(/"/g,""").replace(/\'/g,"&#39;")',
                '.replace(/&/g,"&").replace(/</g,"<").replace(/>/g,">").replace(/"/g,""").replace(/\'/g,"&#39;")'
            )
            changed = True
        marker = "/* NG_BUTTON_FIX_v241 */"
        if marker not in html and "</script>" in html:
            inject = r'''
/* NG_BUTTON_FIX_v241 */
(function(){
  document.addEventListener("click", function(ev){
    var el = ev.target && ev.target.closest ? ev.target.closest("[data-tab],[data-filter],[data-sev],[data-block],[data-unblock],[data-wl],[data-wl-toggle],[data-cap-dl],[data-cap-an],[data-cap-del],button.btn,button.chip,button.nav-item,.side-nav button") : null;
    if(!el) return;
    if(el.dataset && (el.dataset.block||el.dataset.unblock||el.dataset.wl||el.dataset.wlToggle||el.dataset.capDl||el.dataset.capAn||el.dataset.capDel||el.dataset.tab||el.dataset.filter||el.dataset.sev)){
      if(ev.target !== el){
        try { Object.defineProperty(ev, "target", {configurable:true, value:el}); } catch(_){}
      }
    }
  }, true);
  document.addEventListener("pointerdown", function(ev){
    var b = ev.target && ev.target.closest ? ev.target.closest("button,.btn,.chip,.nav-item") : null;
    if(b) b.style.filter="brightness(.9)";
  }, true);
  document.addEventListener("pointerup", function(ev){
    var b = ev.target && ev.target.closest ? ev.target.closest("button,.btn,.chip,.nav-item") : null;
    if(b) b.style.filter="";
  }, true);
  document.addEventListener("pointercancel", function(ev){
    var b = ev.target && ev.target.closest ? ev.target.closest("button,.btn,.chip,.nav-item") : null;
    if(b) b.style.filter="";
  }, true);
  console.log("[NetworkGuard] button reliability patch v2.4.1 active");
})();
'''
            html = html.replace("</script>", inject + "\n</script>", 1)
            changed = True
        if changed:
            ui.write_text(html, encoding="utf-8")
            print(f"Patched ui.html for reliable buttons ({ui.stat().st_size} bytes)", file=sys.stderr)
        else:
            print(f"UI ready ({ui.stat().st_size} bytes)", file=sys.stderr)
    except Exception as exp:
        print(f"UI patch failed: {exp}", file=sys.stderr)

def assemble_b64(pattern, dest_name):
    chunks = sorted(p.glob(pattern))
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

print(f"Final ui.html size: {ui.stat().st_size if ui.exists() else 0}", file=sys.stderr)
PY

if [ -f "${APP_HOME}/ui.html" ]; then
  bashio::log.info "UI ready: $(wc -c < "${APP_HOME}/ui.html") bytes"
else
  bashio::log.warning "No UI file found"
fi

cd "${APP_HOME}"
exec python3 "${APP_HOME}/main.py"
