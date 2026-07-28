from __future__ import annotations

import io

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings
from hypothesis import strategies as st

from py9p import Rread, read_message, write_message
from py9p.io import _read_exact


class FlushBytesIO(io.BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self.flushes = 0

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


class WriteOnlyNoFlush:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, data: bytes) -> int:
        self.data.extend(data)
        return len(data)


@given(data=st.binary(max_size=128))
@settings(max_examples=80, deadline=None)
def test_write_message_flushes_generated_binary_streams(data: bytes, native_so: str) -> None:
    transport = FlushBytesIO()
    message = Rread(data=data)

    written = write_message(transport, message)

    assert written == len(transport.getvalue())
    assert transport.flushes == 1
    transport.seek(0)
    assert read_message(transport) == message


@given(data=st.binary(max_size=128))
@settings(max_examples=80, deadline=None)
def test_write_message_accepts_generated_streams_without_flush(
    data: bytes, native_so: str
) -> None:
    transport = WriteOnlyNoFlush()
    message = Rread(data=data)
    assert write_message(transport, message) == len(transport.data)
    assert read_message(io.BytesIO(transport.data)) == message


@given(data=st.binary(max_size=128))
@settings(max_examples=80, deadline=None)
def test_read_message_accepts_generated_exact_max_size(data: bytes, native_so: str) -> None:
    message = Rread(data=data)
    wire = message.to_bytes()
    assert read_message(io.BytesIO(wire), max_size=len(wire)) == message


@given(chunks=st.lists(st.binary(max_size=8), max_size=8))
@settings(max_examples=30, deadline=None)
def test_read_exact_zero_size_ignores_generated_transport_data(chunks: list[bytes]) -> None:
    transport = io.BytesIO(b"".join(chunks))
    assert _read_exact(transport, 0) == b""
    assert transport.tell() == 0
