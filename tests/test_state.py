#!/usr/bin/env python3
"""State store tests."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fritzbox_network_guard" / "rootfs" / "app"))

from state import StateStore


def test_atomic_save_and_audit():
    with tempfile.TemporaryDirectory() as td:
        st = StateStore(Path(td))
        st.upsert_device("AA:BB:CC:DD:EE:FF", {"ip": "192.168.178.10", "mac": "AA:BB:CC:DD:EE:FF"})
        st.save()
        assert (Path(td) / "state.json").exists()
        st.audit("user", "block", mac="AA:BB:CC:DD:EE:FF", ip="192.168.178.10", reason="test")
        events = st.read_audit(10)
        assert events and events[0]["action"] == "block"


if __name__ == "__main__":
    test_atomic_save_and_audit()
    print("state tests OK")
