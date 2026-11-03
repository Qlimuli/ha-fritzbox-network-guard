#!/usr/bin/env python3
"""Assembler: loads main_p1 + main_p2 into one module namespace."""
from pathlib import Path
_p = Path(__file__).resolve().parent
_code = (_p / "main_p1.py").read_text(encoding="utf-8") + "\n" + (_p / "main_p2.py").read_text(encoding="utf-8")
exec(compile(_code, str(_p / "main_assembled.py"), "exec"), globals())
