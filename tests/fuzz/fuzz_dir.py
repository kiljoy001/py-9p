"""Atheris harness for arbitrary 9P stat bytes."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from py9p import CodecError, Dir


def _one(data: bytes) -> None:
    try:
        entry = Dir.from_bytes(data)
    except (CodecError, UnicodeDecodeError, ValueError):
        return
    entry.to_bytes()


def main() -> None:
    atheris.Setup(sys.argv, _one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
