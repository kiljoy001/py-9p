from __future__ import annotations

import io

import pytest

from py9p import ProtocolError, Rread, Tversion, read_message, write_message
from py9p.io import _read_exact


class ShortWrite:
    def write(self, data: bytes) -> int:
        return len(data) - 1


class NonBytesRead:
    def read(self, size: int):
        return "not bytes"


class FragmentedRead:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks
        self.sizes: list[int] = []

    def read(self, size: int):
        self.sizes.append(size)
        return self.chunks.pop(0)


class OverRead:
    def read(self, size: int):
        return b"x" * (size + 1)


def test_write_message_to_binary_stream(native_so):
    buf = io.BytesIO()
    assert write_message(buf, Tversion(msize=8192)) == len(Tversion(msize=8192).to_bytes())
    buf.seek(0)
    assert read_message(buf) == Tversion(msize=8192)


def test_write_message_rejects_short_stream_write(native_so):
    with pytest.raises(Exception, match="short write"):
        write_message(ShortWrite(), Rread(data=b"abc"))  # type: ignore[arg-type]


def test_read_message_rejects_eof():
    with pytest.raises(EOFError, match="connection closed"):
        read_message(io.BytesIO(b"\x07\x00"))


def test_read_message_rejects_invalid_size():
    with pytest.raises(ProtocolError, match="invalid 9P message size"):
        read_message(io.BytesIO(b"\x06\x00\x00\x00xx"))


def test_read_message_rejects_too_large_size():
    with pytest.raises(ProtocolError, match="exceeds max_size"):
        read_message(io.BytesIO(b"\x08\x00\x00\x00xxxx"), max_size=7)


def test_read_exact_rejects_non_bytes():
    with pytest.raises(TypeError, match="non-bytes"):
        read_message(NonBytesRead())  # type: ignore[arg-type]


def test_read_exact_accepts_fragmented_reads():
    transport = FragmentedRead([b"a", b"bc", b"d"])
    assert _read_exact(transport, 4) == b"abcd"  # type: ignore[arg-type]
    assert transport.sizes == [4, 3, 1]


def test_read_exact_rejects_transport_overread():
    with pytest.raises(ProtocolError, match="more bytes than requested"):
        _read_exact(OverRead(), 4)  # type: ignore[arg-type]


def test_read_exact_rejects_negative_size():
    with pytest.raises(ValueError, match="non-negative"):
        _read_exact(io.BytesIO(), -1)
