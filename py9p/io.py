"""Read and write framed 9P messages on sockets or binary streams."""

from __future__ import annotations

import socket
from typing import BinaryIO

from .messages import CodecError, Message, ProtocolError
from .native import decode_message, encode_message

DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024


def _read_exact(transport: BinaryIO | socket.socket, size: int) -> bytes:
    if size < 0:
        raise ValueError("read size must be non-negative")  # pragma: no mutate
    chunks: list[bytes] = []
    remaining = size
    for _ in range(size):
        if remaining == 0:
            break
        if hasattr(transport, "recv"):
            chunk = transport.recv(remaining)  # type: ignore[attr-defined]
        else:
            chunk = transport.read(remaining)  # type: ignore[attr-defined]
        if not isinstance(chunk, bytes):
            raise TypeError("transport read returned non-bytes data")  # pragma: no mutate
        chunk_len = len(chunk)
        if chunk_len == 0:
            raise EOFError("connection closed while reading a 9P message")  # pragma: no mutate
        if chunk_len > remaining:
            raise ProtocolError("transport returned more bytes than requested")  # pragma: no mutate
        chunks.append(chunk)
        remaining -= chunk_len
    if remaining:
        raise EOFError("connection closed while reading a 9P message")  # pragma: no mutate
    return b"".join(chunks)


def read_message(
    transport: BinaryIO | socket.socket,
    max_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> Message:
    header = _read_exact(transport, 4)
    size = int.from_bytes(header, "little")
    if size < 7:
        raise ProtocolError(f"invalid 9P message size {size}")  # pragma: no mutate
    if size > max_size:
        raise ProtocolError(f"9P message size {size} exceeds max_size {max_size}")  # pragma: no mutate
    return decode_message(header + _read_exact(transport, size - 4))


def write_message(transport: BinaryIO | socket.socket, message: Message) -> int:
    data = encode_message(message)
    if hasattr(transport, "sendall"):
        transport.sendall(data)  # type: ignore[attr-defined]
    else:
        written = transport.write(data)  # type: ignore[attr-defined]
        if written not in (None, len(data)):
            raise CodecError("short write while sending a 9P message")  # pragma: no mutate
        flush = getattr(transport, "flush", None)
        if flush is not None:
            flush()
    return len(data)
