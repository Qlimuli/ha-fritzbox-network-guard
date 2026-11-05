#!/usr/bin/env python3
"""FritzBox packet capture (hidden AVM capture endpoint) + analysis helpers.

Uses the same undocumented but widely used capture endpoint that Wireshark
extcap plugins rely on:

  https://<fritz>/cgi-bin/capture_notimeout?sid=...&capture=Start&ifaceorminor=...

Produces standard PCAP streams that can be downloaded and opened in Wireshark.
Also provides lightweight stats via tshark when available.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import requests

log = logging.getLogger("packet-capture")

# Common FritzBox capture interfaces (see also ?lp=cap and fritzcap tables)
DEFAULT_IFACES = [
    {"id": "1-lan", "name": "LAN (bridge)"},
    {"id": "2-1", "name": "Internet (WAN)"},
    {"id": "1-eth0", "name": "Physical LAN1"},
    {"id": "1-eth1", "name": "Physical LAN2"},
    {"id": "1-eth2", "name": "Physical LAN3"},
    {"id": "1-eth3", "name": "Physical LAN4"},
    {"id": "4-133", "name": "WLAN 2.4 GHz"},
    {"id": "4-135", "name": "WLAN 5 GHz"},
]

CAPTURE_DIR = Path(os.getenv("DATA_DIR", "/data")) / "captures"


class PacketCapture:
    def __init__(
        self,
        host: str,
        get_sid: Callable[[], str | None],
        password: str = "",
        user: str = "",
    ):
        self.host = host.rstrip("/").replace("https://", "").replace("http://", "")
        self._get_sid = get_sid
        self.password = password
        self.user = user
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._status: dict[str, Any] = {
            "running": False,
            "iface": None,
            "started_at": None,
            "file": None,
            "bytes": 0,
            "error": None,
            "pid": None,
        }
        self._lock = threading.Lock()
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    def list_interfaces(self) -> list[dict]:
        return list(DEFAULT_IFACES)

    def status(self) -> dict[str, Any]:
        with self._lock:
            st = dict(self._status)
            if st.get("file") and Path(st["file"]).exists():
                try:
                    st["bytes"] = Path(st["file"]).stat().st_size
                except OSError:
                    pass
            return st

    def _base_url(self) -> str:
        return f"https://{self.host}"

    def _sid(self) -> str | None:
        sid = self._get_sid()
        if sid:
            return sid
        return None

    def start(self, iface: str = "1-lan", snaplen: int = 0, duration_sec: int = 0) -> dict:
        with self._lock:
            if self._status.get("running"):
                return {"ok": False, "message": "Capture already running", "status": self.status()}

            sid = self._sid()
            if not sid:
                return {"ok": False, "message": "No valid FritzBox SID – check credentials / login"}

            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            fname = CAPTURE_DIR / f"fritz_{iface.replace('-', '_')}_{ts}.pcap"
            url = (
                f"{self._base_url()}/cgi-bin/capture_notimeout"
                f"?sid={quote(sid)}&capture=Start&snaplen={snaplen or ''}"
                f"&ifaceorminor={quote(iface)}"
            )

            try:
                requests.get(
                    f"{self._base_url()}/cgi-bin/capture_notimeout"
                    f"?sid={quote(sid)}&capture=Stop&ifaceorminor={quote(iface)}",
                    timeout=5,
                    verify=False,
                )
            except Exception:
                pass

            self._stop.clear()
            self._status = {
                "running": True,
                "iface": iface,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "file": str(fname),
                "bytes": 0,
                "error": None,
                "pid": None,
                "url": url.split("?")[0],
            }

            def _run():
                try:
                    cmd = [
                        "curl",
                        "--insecure",
                        "--silent",
                        "--no-buffer",
                        "--max-time",
                        str(duration_sec or 3600),
                        url,
                        "-o",
                        str(fname),
                    ]
                    self._proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        preexec_fn=os.setsid,
                    )
                    with self._lock:
                        self._status["pid"] = self._proc.pid
                    self._proc.wait()
                    if self._proc.returncode not in (0, None) and not self._stop.is_set():
                        err = (self._proc.stderr.read() or b"").decode(errors="replace")[:300]
                        with self._lock:
                            self._status["error"] = err or f"curl exit {self._proc.returncode}"
                except Exception as exc:
                    with self._lock:
                        self._status["error"] = str(exc)
                finally:
                    try:
                        sid2 = self._sid()
                        if sid2:
                            requests.get(
                                f"{self._base_url()}/cgi-bin/capture_notimeout"
                                f"?sid={quote(sid2)}&capture=Stop&ifaceorminor={quote(iface)}",
                                timeout=5,
                                verify=False,
                            )
                    except Exception:
                        pass
                    with self._lock:
                        self._status["running"] = False
                        if fname.exists():
                            self._status["bytes"] = fname.stat().st_size

            self._thread = threading.Thread(target=_run, daemon=True)
            self._thread.start()
            return {"ok": True, "message": f"Capture started on {iface}", "status": self.status()}

    def stop(self) -> dict:
        with self._lock:
            self._stop.set()
            proc = self._proc
            iface = self._status.get("iface") or "1-lan"
            sid = self._sid()
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass
        if sid:
            try:
                requests.get(
                    f"{self._base_url()}/cgi-bin/capture_notimeout"
                    f"?sid={quote(sid)}&capture=Stop&ifaceorminor={quote(iface)}",
                    timeout=5,
                    verify=False,
                )
            except Exception:
                pass
        time.sleep(0.5)
        return {"ok": True, "message": "Capture stop requested", "status": self.status()}

    def list_captures(self) -> list[dict]:
        out = []
        for p in sorted(CAPTURE_DIR.glob("*.pcap"), reverse=True):
            try:
                st = p.stat()
                out.append(
                    {
                        "name": p.name,
                        "path": str(p),
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                    }
                )
            except OSError:
                pass
        return out

    def delete_capture(self, name: str) -> dict:
        safe = Path(name).name
        p = CAPTURE_DIR / safe
        if not p.exists() or not p.suffix == ".pcap":
            return {"ok": False, "message": "File not found"}
        p.unlink()
        return {"ok": True, "message": f"Deleted {safe}"}

    def analyze(self, name: str, limit: int = 50) -> dict:
        """Lightweight analysis with tshark if present, else basic file info."""
        safe = Path(name).name
        p = CAPTURE_DIR / safe
        if not p.exists():
            return {"ok": False, "message": "File not found"}

        result: dict[str, Any] = {
            "ok": True,
            "file": safe,
            "size": p.stat().st_size,
            "tshark": False,
            "summary": {},
            "top_talkers": [],
            "protocols": [],
            "packets_preview": [],
        }

        tshark = shutil.which("tshark")
        if not tshark:
            result["message"] = "tshark not installed – only file metadata available"
            return result

        result["tshark"] = True
        try:
            cap = subprocess.run(
                [tshark, "-r", str(p), "-q", "-z", "io,stat,0"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            result["io_stat"] = (cap.stdout or "")[:2000]

            ph = subprocess.run(
                [tshark, "-r", str(p), "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            result["protocol_hierarchy"] = (ph.stdout or "")[:4000]

            ep = subprocess.run(
                [tshark, "-r", str(p), "-q", "-z", "endpoints,ip"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            result["endpoints"] = (ep.stdout or "")[:3000]

            pkts = subprocess.run(
                [
                    tshark,
                    "-r",
                    str(p),
                    "-T",
                    "fields",
                    "-e",
                    "frame.number",
                    "-e",
                    "frame.time_relative",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                    "-e",
                    "frame.protocols",
                    "-e",
                    "frame.len",
                    "-c",
                    str(limit),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            lines = []
            for line in (pkts.stdout or "").splitlines():
                parts = line.split("\t")
                if len(parts) >= 6:
                    lines.append(
                        {
                            "no": parts[0],
                            "time": parts[1],
                            "src": parts[2],
                            "dst": parts[3],
                            "proto": parts[4],
                            "len": parts[5],
                        }
                    )
            result["packets_preview"] = lines
        except subprocess.TimeoutExpired:
            result["error"] = "tshark analysis timed out"
        except Exception as exc:
            result["error"] = str(exc)
        return result
