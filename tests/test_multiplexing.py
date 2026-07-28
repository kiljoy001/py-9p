from __future__ import annotations

import socket
import threading

import pytest

from py9p import Client, NinePError, Rread, Tread, read_message, write_message


def _serve_reversed_reads(server_sock: socket.socket, count: int) -> None:
    try:
        requests = [read_message(server_sock) for _ in range(count)]
        assert len({request.tag for request in requests}) == count
        for request in reversed(requests):
            assert isinstance(request, Tread)
            data = f"{request.fid}:{request.offset}:{request.count}".encode()
            write_message(server_sock, Rread(data=data, tag=request.tag))
    finally:
        server_sock.close()


@pytest.mark.native
def test_low_level_io_preserves_multiplexed_tags_with_out_of_order_replies(native_so):
    client_sock, server_sock = socket.socketpair()
    requests = tuple(
        Tread(fid=7, offset=offset, count=10, tag=tag)
        for tag, offset in ((10, 0), (11, 10), (12, 20), (13, 30))
    )

    thread = threading.Thread(target=_serve_reversed_reads, args=(server_sock, len(requests)))
    thread.start()
    try:
        for request in requests:
            write_message(client_sock, request)

        replies = [read_message(client_sock, max_size=8192) for _ in requests]
    finally:
        client_sock.close()
        thread.join(timeout=2)

    assert [reply.tag for reply in replies] == [13, 12, 11, 10]
    assert {reply.tag: reply.data for reply in replies} == {
        request.tag: f"{request.fid}:{request.offset}:{request.count}".encode()
        for request in requests
    }


@pytest.mark.native
def test_client_multiplexes_concurrent_helper_calls(native_so):
    client_sock, server_sock = socket.socketpair()
    client_sock.settimeout(2)
    server_sock.settimeout(2)
    offsets = (0, 10, 20, 30)
    server_thread = threading.Thread(target=_serve_reversed_reads, args=(server_sock, len(offsets)))
    results: dict[int, bytes] = {}
    errors: list[BaseException] = []

    def read_at(client: Client, offset: int) -> None:
        try:
            results[offset] = client.read(fid=7, offset=offset, count=10)
        except (EOFError, NinePError, OSError) as exc:  # pragma: no cover - reported below
            errors.append(exc)

    server_thread.start()
    try:
        with Client(client_sock, msize=8192) as client:
            threads = [threading.Thread(target=read_at, args=(client, offset)) for offset in offsets]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)
    finally:
        client_sock.close()
        server_thread.join(timeout=2)

    assert errors == []
    assert results == {offset: f"7:{offset}:10".encode() for offset in offsets}
