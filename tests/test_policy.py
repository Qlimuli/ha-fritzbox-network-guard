#!/usr/bin/env python3
"""Unit tests for safety policy (no Fritz required)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fritzbox_network_guard" / "rootfs" / "app"))

from policy import (
    PolicyConfig,
    SafetyPolicy,
    is_randomized_mac,
    is_valid_ipv4,
    is_valid_mac,
    norm_mac,
)
from risk import score_device


def test_norm_mac():
    assert norm_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert is_valid_mac("AA:BB:CC:DD:EE:FF")
    assert not is_valid_mac("zz")


def test_randomized_mac():
    assert is_randomized_mac("02:11:22:33:44:55")
    assert not is_randomized_mac("00:11:22:33:44:55")


def test_circuit_breaker_empty():
    cfg = PolicyConfig()
    p = SafetyPolicy(cfg)
    trip, reason = p.circuit_breaker(0, True, 0)
    assert trip and reason == "empty_host_list"


def test_mode_learning_no_auto():
    cfg = PolicyConfig(mode="learning", auto_block_new_devices=True)
    p = SafetyPolicy(cfg)
    allow, reason = p.allow_auto_block(
        ip="192.168.178.99", mac="11:22:33:44:55:66",
        is_new=True, active=True, learning_complete=False,
    )
    assert not allow and reason == "mode_learning"


def test_risk_score():
    s, factors = score_device(open_ports=[23, 445], is_new=True, mac="02:11:22:33:44:55")
    assert s >= 30
    assert any(f["code"] == "port_23" for f in factors)


if __name__ == "__main__":
    test_norm_mac()
    test_randomized_mac()
    test_circuit_breaker_empty()
    test_mode_learning_no_auto()
    test_risk_score()
    print("all policy tests OK")
