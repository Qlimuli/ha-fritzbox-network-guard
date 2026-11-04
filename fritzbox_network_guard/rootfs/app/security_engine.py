#!/usr/bin/env python3
"""Placeholder overwritten at container start by run.sh from security_engine.b64.* chunks.
Do not ship broken content like the string "test" – that causes NameError on import.
"""
from __future__ import annotations

class SecurityEngine:
    """Minimal stub; real implementation is assembled from gzip+b64 chunks at runtime."""

    def __init__(self, *args, **kwargs):
        raise RuntimeError(
            "security_engine.py was not assembled from chunks. "
            "Ensure security_engine.b64.00–03 exist and run.sh assemble runs."
        )

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def status(self) -> dict:
        return {"error": "not assembled"}

    def list_events(self, limit: int = 50):
        return []
