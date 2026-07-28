"""Atheris harness for arbitrary 9P message bytes."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from py9p import CodecError, decode_message, encode_message


def _one(data: bytes) -> None:
    try:
        msg = decode_message(data)
    except (CodecError, UnicodeDecodeError, ValueError):
        return
    try:
        encode_message(msg)
    except (CodecError, UnicodeDecodeError, ValueError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, _one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
