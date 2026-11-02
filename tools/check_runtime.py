"""Verify the interpreter and pinned dependencies match the lock file.

Run before any qualification or release step:

    PYTHONPATH=src:. python3 tools/check_runtime.py

Exits non-zero when the environment differs from ``requirements-lock.txt``
or the interpreter is outside the supported range, so a result measured in
a drifted environment can never be reported as a pinned-runtime result.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements-lock.txt"
MIN_PYTHON = (3, 10)
MAX_PYTHON_EXCLUSIVE = (4, 0)
_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*"
                   r"([A-Za-z0-9.+!-]+)$")


def read_lock(path: Path = LOCK) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = _NAME.match(line)
        if match is None:
            raise SystemExit(f"unpinned or malformed requirement: {line!r}")
        pins[match.group(1).lower()] = match.group(2)
    return pins


def installed(name: str) -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - Python < 3.8
        return None
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def main() -> int:
    problems: list[str] = []
    here = sys.version_info[:2]
    if here < MIN_PYTHON:
        problems.append(
            f"python {here[0]}.{here[1]} is older than "
            f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}")
    if here >= MAX_PYTHON_EXCLUSIVE:
        problems.append(
            f"python {here[0]}.{here[1]} is not qualified "
            f"(< {MAX_PYTHON_EXCLUSIVE[0]}.{MAX_PYTHON_EXCLUSIVE[1]})")
    pins = read_lock()
    for name, expected in sorted(pins.items()):
        actual = installed(name)
        if actual is None:
            problems.append(f"{name}=={expected} is not installed")
        elif actual != expected:
            problems.append(f"{name}=={actual} but lock pins {expected}")
    print(f"python: {sys.version.split()[0]}")
    print(f"lock:   {LOCK.name} ({len(pins)} pins)")
    if problems:
        for problem in problems:
            print("MISMATCH " + problem)
        print(f"\nruntime does not match the pinned profile "
              f"({len(problems)} problem(s))")
        return 1
    print("runtime matches the pinned profile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
