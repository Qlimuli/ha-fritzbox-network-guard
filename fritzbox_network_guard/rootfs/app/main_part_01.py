#!/usr/bin/env python3
"""FritzBox Network Guard – production WSGI + rich UI + SecurityEngine."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from fritzconnection import FritzConnection
import requests
from mac_guard import MacQuarantine, norm_mac
from security_engine import SecurityEngine

FRITZBOX_HOST = os.getenv("FRITZBOX_HOST", "fritz.box")
FRITZBOX_USER = os.getenv("FRITZBOX_USER", "")
FRITZBOX_PASSWORD = os.getenv("FRITZBOX_PASSWORD", "")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))
NETWORK_CIDR = os.getenv("NETWORK_CIDR", "192.168.178.0/24")
CRITICAL_MAC_PREFIXES = [
    p.strip().upper().replace("-", ":")
    for p in os.getenv("CRITICAL_MAC_PREFIXES", "").split(",")
    if p.strip()
]
AUTO_BLOCK_NEW = os.getenv("AUTO_BLOCK_NEW", "false").lower() in ("true", "1", "yes")
NOTIFY_ON_BLOCK = os.getenv("NOTIFY_ON_BLOCK", "true").lower() in ("true", "1", "yes")
ENABLE_PERIMETER = os.getenv("ENABLE_PERIMETER_SCAN", "true").lower() in ("true", "1", "yes")
PERIMETER_INTERVAL = int(os.getenv("PERIMETER_INTERVAL", "3600"))
ENABLE_THREAT_INTEL = os.getenv("ENABLE_THREAT_INTEL", "true").lower() in ("true", "1", "yes")
THREAT_INTEL_INTERVAL = int(os.getenv("THREAT_INTEL_INTERVAL", "21600"))
AUTO_BLOCK_THREAT_INTEL = os.getenv("AUTO_BLOCK_THREAT_INTEL", "true").lower() in ("true", "1", "yes")
SUPERVISOR_TOKEN = os.getenv("SUPERVISOR_TOKEN", "")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
APP_DIR = Path(__file__).resolve().parent
BLOCKED_FILE = DATA_DIR / "blocked_devices.json"
KNOWN_FILE = DATA_DIR / "known_devices.json"
