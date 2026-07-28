from __future__ import annotations

import getpass
import os
import secrets

import pytest

from py9p import (
    OREAD,
    OWRITE,
    QTDIR,
    VERSION9P,
    Client,
    Message,
    RemoteError,
    Rread,
    Rwrite,
    Tread,
    Twrite,
    read_message,
    write_message,
)


def _parse_port(port: str, name: str) -> int:
    try:
        return int(port)
    except ValueError:
        pytest.skip(f"{name} must be an integer")


def _remote_target() -> tuple[str, int]:
    host = os.environ.get("PY9P_9FRONT_HOST")
    port = os.environ.get("PY9P_9FRONT_PORT")
    if not host or not port:
        pytest.skip("set PY9P_9FRONT_HOST and PY9P_9FRONT_PORT for remote 9front tests")
    return host, _parse_port(port, "PY9P_9FRONT_PORT")


def _write_target() -> tuple[str, int]:
    if os.environ.get("PY9P_9FRONT_WRITE") != "1":
        pytest.skip("set PY9P_9FRONT_WRITE=1 to run remote write tests")
    host = os.environ.get("PY9P_9FRONT_WRITE_HOST") or os.environ.get("PY9P_9FRONT_HOST")
    port = os.environ.get("PY9P_9FRONT_WRITE_PORT") or os.environ.get("PY9P_9FRONT_PORT")
    if not host or not port:
        pytest.skip("set PY9P_9FRONT_WRITE_HOST and PY9P_9FRONT_WRITE_PORT")
    return host, _parse_port(port, "PY9P_9FRONT_WRITE_PORT")


def _path_elements(path: str) -> tuple[str, ...]:
    return tuple(part for part in path.split("/") if part and part != ".")


def _read_tagged_replies(
    client: Client,
    expected_tags: set[int],
    expected_type: type[Message],
) -> dict[int, Message]:
    replies: dict[int, Message] = {}
    for _ in expected_tags:
        reply = read_message(client.transport, max_size=client.msize)
        assert isinstance(reply, expected_type)
        assert reply.tag in expected_tags
        assert reply.tag not in replies
        replies[reply.tag] = reply
    assert set(replies) == expected_tags
    return replies


@pytest.mark.native
@pytest.mark.remote
def test_client_reads_file_from_9front_exportfs(native_so):
    host, port = _remote_target()
    uname = os.environ.get("PY9P_9FRONT_USER") or getpass.getuser()
    path = os.environ.get("PY9P_9FRONT_READ_PATH", "lib/namespace")
    path_elements = _path_elements(path)
    if not path_elements:
        pytest.skip("PY9P_9FRONT_READ_PATH must name a file below the exported root")

    with Client.connect_tcp(host, port, timeout=8, msize=8192) as client:
        version = client.negotiate()
        assert version.version == VERSION9P
        assert 7 <= version.msize <= 8192

        root_qid = client.attach(fid=0, uname=uname)
        assert root_qid.type & int(QTDIR)

        walked = client.walk(fid=0, newfid=1, path=path)
        assert len(walked) == len(path_elements)

        qid, iounit = client.open(fid=1, mode=int(OREAD))
        assert qid == walked[-1]
        assert 0 <= iounit <= client.msize

        data = client.read(fid=1, count=256)
        assert data
        assert len(data) <= 256

        client.clunk(fid=1)
        with pytest.raises(RemoteError):
            client.read(fid=1, count=1)
        client.clunk(fid=0)


@pytest.mark.native
@pytest.mark.remote
def test_client_writes_reads_and_removes_file_on_9front_ramfs(native_so):
    host, port = _write_target()
    uname = os.environ.get("PY9P_9FRONT_USER") or getpass.getuser()
    write_dir = _path_elements(os.environ.get("PY9P_9FRONT_WRITE_DIR", ""))
    name = f"py9p-write-smoke-{secrets.token_hex(8)}.txt"
    payload = b"py9p remote ramfs write smoke\n"

    with Client.connect_tcp(host, port, timeout=8, msize=8192) as client:
        version = client.negotiate()
        assert version.version == VERSION9P

        client.attach(fid=0, uname=uname)
        client.walk(fid=0, newfid=1, path=write_dir)
        _, iounit = client.create(fid=1, name=name, perm=0o666, mode=int(OWRITE))
        assert 0 <= iounit <= client.msize
        assert client.write(fid=1, data=payload) == len(payload)
        client.clunk(fid=1)

        client.walk(fid=0, newfid=2, path=(*write_dir, name))
        client.open(fid=2, mode=int(OREAD))
        assert client.read(fid=2, count=len(payload) + 1) == payload
        client.clunk(fid=2)

        client.walk(fid=0, newfid=3, path=(*write_dir, name))
        client.remove(fid=3)
        client.clunk(fid=0)


@pytest.mark.native
@pytest.mark.remote
def test_low_level_reads_multiple_outstanding_requests_from_9front_exportfs(native_so):
    host, port = _remote_target()
    uname = os.environ.get("PY9P_9FRONT_USER") or getpass.getuser()
    path = os.environ.get("PY9P_9FRONT_READ_PATH", "lib/namespace")

    with Client.connect_tcp(host, port, timeout=8, msize=8192) as client:
        client.negotiate()
        client.attach(fid=0, uname=uname)
        client.walk(fid=0, newfid=1, path=path)
        client.open(fid=1, mode=int(OREAD))

        baseline = client.read(fid=1, count=192)
        if len(baseline) < 3:
            pytest.skip("remote read target is too small for a multiplexed read smoke")
        chunk_size = min(64, max(1, len(baseline) // 3))
        offsets = (0, chunk_size, chunk_size * 2)
        requests = tuple(
            Tread(fid=1, offset=offset, count=chunk_size, tag=200 + index)
            for index, offset in enumerate(offsets)
        )

        for request in requests:
            write_message(client.transport, request)

        replies = _read_tagged_replies(client, {request.tag for request in requests}, Rread)
        for request in requests:
            reply = replies[request.tag]
            assert isinstance(reply, Rread)
            assert reply.data == baseline[request.offset : request.offset + request.count]

        client.clunk(fid=1)
        client.clunk(fid=0)


@pytest.mark.native
@pytest.mark.remote
def test_low_level_writes_multiple_outstanding_requests_to_9front_ramfs(native_so):
    host, port = _write_target()
    uname = os.environ.get("PY9P_9FRONT_USER") or getpass.getuser()
    write_dir = _path_elements(os.environ.get("PY9P_9FRONT_WRITE_DIR", ""))
    name = f"py9p-mux-write-smoke-{secrets.token_hex(8)}.txt"
    chunks = (b"first\n", b"second\n", b"third\n", b"fourth\n")
    offsets = []
    cursor = 0
    for chunk in chunks:
        offsets.append(cursor)
        cursor += len(chunk)

    with Client.connect_tcp(host, port, timeout=8, msize=8192) as client:
        client.negotiate()
        client.attach(fid=0, uname=uname)
        client.walk(fid=0, newfid=1, path=write_dir)
        client.create(fid=1, name=name, perm=0o666, mode=int(OWRITE))

        requests = tuple(
            Twrite(fid=1, offset=offset, data=chunk, tag=300 + index)
            for index, (offset, chunk) in enumerate(zip(offsets, chunks))
        )
        for request in requests:
            write_message(client.transport, request)

        replies = _read_tagged_replies(client, {request.tag for request in requests}, Rwrite)
        for request in requests:
            reply = replies[request.tag]
            assert isinstance(reply, Rwrite)
            assert reply.count == len(request.data)
        client.clunk(fid=1)

        payload = b"".join(chunks)
        client.walk(fid=0, newfid=2, path=(*write_dir, name))
        client.open(fid=2, mode=int(OREAD))
        assert client.read(fid=2, count=len(payload) + 1) == payload
        client.clunk(fid=2)

        client.walk(fid=0, newfid=3, path=(*write_dir, name))
        client.remove(fid=3)
        client.clunk(fid=0)
