from __future__ import annotations

import socket
import threading
import time

import pytest

from py9p import (
    IOHDRSZ,
    NOFID,
    NOTAG,
    Client,
    Dir,
    Qid,
    Rattach,
    Rclunk,
    Rcreate,
    Rerror,
    Ropen,
    Rread,
    Rremove,
    Rstat,
    Rversion,
    Rwalk,
    Rwrite,
    Rwstat,
    Tattach,
    Tclunk,
    Tcreate,
    Topen,
    Tread,
    Tremove,
    Tstat,
    Tversion,
    Twalk,
    Twrite,
    Twstat,
    read_message,
    write_message,
)
from py9p import client as client_mod
from py9p.client import ProtocolError, RemoteError


def _serve_once(server_sock: socket.socket, replies: list[object], seen: list[object]) -> None:
    try:
        for reply in replies:
            req = read_message(server_sock)
            seen.append(req)
            if callable(reply):
                reply = reply(req)
            write_message(server_sock, reply)  # type: ignore[arg-type]
    finally:
        server_sock.close()


@pytest.mark.native
def test_client_negotiate_attach_read_clunk(native_so):
    client_sock, server_sock = socket.socketpair()
    seen: list[object] = []

    def version(req):
        assert isinstance(req, Tversion)
        return Rversion(msize=req.msize, version=req.version, tag=req.tag)

    def attach(req):
        assert isinstance(req, Tattach)
        return Rattach(qid=Qid(type=0x80, vers=1, path=2), tag=req.tag)

    def read(req):
        assert isinstance(req, Tread)
        return Rread(data=b"hello", tag=req.tag)

    def clunk(req):
        assert isinstance(req, Tclunk)
        return Rclunk(tag=req.tag)

    thread = threading.Thread(
        target=_serve_once,
        args=(server_sock, [version, attach, read, clunk], seen),
    )
    thread.start()
    try:
        with Client(client_sock, msize=8192) as client:
            assert client.negotiate().version == "9P2000"
            assert client.attach(fid=0, uname="glenda").path == 2
            assert client.read(fid=1, count=5) == b"hello"
            client.clunk(fid=1)
    finally:
        client_sock.close()
        thread.join(timeout=2)

    assert [type(req) for req in seen] == [Tversion, Tattach, Tread, Tclunk]


@pytest.mark.native
def test_client_rerror_raises(native_so):
    client_sock, server_sock = socket.socketpair()
    seen: list[object] = []
    thread = threading.Thread(
        target=_serve_once,
        args=(server_sock, [lambda req: Rerror(ename="nope", tag=req.tag)], seen),
    )
    thread.start()
    try:
        with Client(client_sock) as client, pytest.raises(RemoteError, match="nope"):
            client.rpc(Tread(fid=1, count=1), Rread)
    finally:
        client_sock.close()
        thread.join(timeout=2)


@pytest.mark.native
def test_client_covers_all_helper_methods(native_so):
    client_sock, server_sock = socket.socketpair()
    seen: list[object] = []
    stat_entry = Dir(qid=Qid(type=0, vers=3, path=4), name="n", uid="u", gid="g", muid="m")

    def walk(req):
        assert isinstance(req, Twalk)
        assert req.fid == 0
        assert req.newfid == 1
        assert req.wname == ("usr", "glenda")
        return Rwalk(wqid=(Qid(type=0x80, vers=1, path=2), Qid(type=0, vers=2, path=3)), tag=req.tag)

    def open_(req):
        assert isinstance(req, Topen)
        assert req.fid == 1
        assert req.mode == 2
        return Ropen(qid=Qid(type=0, vers=2, path=3), iounit=1024, tag=req.tag)

    def create(req):
        assert isinstance(req, Tcreate)
        assert (req.fid, req.name, req.perm, req.mode) == (1, "new", 0o644, 1)
        return Rcreate(qid=Qid(type=0, vers=4, path=5), iounit=2048, tag=req.tag)

    def write(req):
        assert isinstance(req, Twrite)
        assert (req.fid, req.offset, req.data) == (1, 9, b"abc")
        return Rwrite(count=3, tag=req.tag)

    def remove(req):
        assert isinstance(req, Tremove)
        assert req.fid == 1
        return Rremove(tag=req.tag)

    def stat(req):
        assert isinstance(req, Tstat)
        assert req.fid == 2
        return Rstat(stat=stat_entry, tag=req.tag)

    def wstat(req):
        assert isinstance(req, Twstat)
        assert req.fid == 2
        return Rwstat(tag=req.tag)

    thread = threading.Thread(
        target=_serve_once,
        args=(server_sock, [walk, open_, create, write, remove, stat, wstat], seen),
    )
    thread.start()
    try:
        with Client(client_sock, msize=4096) as client:
            assert len(client.walk(0, 1, "usr/glenda")) == 2
            assert client.open(1, mode=2) == (Qid(type=0, vers=2, path=3), 1024)
            assert client.create(1, "new", 0o644, mode=1) == (Qid(type=0, vers=4, path=5), 2048)
            assert client.write(1, b"abc", offset=9) == 3
            client.remove(1)
            assert client.stat(2) == stat_entry
            client.wstat(2, stat_entry)
    finally:
        client_sock.close()
        thread.join(timeout=2)

    assert [type(req) for req in seen] == [Twalk, Topen, Tcreate, Twrite, Tremove, Tstat, Twstat]


def test_client_close_is_idempotent_and_blocks_rpc():
    class FakeTransport:
        def __init__(self):
            self.closed = 0

        def close(self):
            self.closed += 1

    transport = FakeTransport()
    client = Client(transport)  # type: ignore[arg-type]
    client.close()
    client.close()
    assert transport.closed == 1
    with pytest.raises(ProtocolError) as exc:
        client.rpc(Tread(fid=1, count=1), Rread)
    assert str(exc.value) == "client is closed"


def test_client_close_allows_transport_without_close():
    client = Client(object())  # type: ignore[arg-type]
    client.close()
    assert client._closed is True


def test_client_tag_allocator_skips_notag():
    client = Client(object())  # type: ignore[arg-type]
    assert client._tag() == 0
    assert client._tag() == 1

    client._next_tag = NOTAG - 1
    assert client._tag() == NOTAG - 1
    assert client._next_tag == 0
    assert client._tag() == 0


def test_client_type_name_formats_single_and_tuple():
    assert Client._type_name(Rread) == "Rread"
    assert Client._type_name((Rread, Rerror)) == "Rread or Rerror"


def test_connect_helpers_use_socket_factories(monkeypatch):
    made = object()
    tcp_calls: list[tuple[object, object]] = []

    def fake_create_connection(addr, timeout=None):
        tcp_calls.append((addr, timeout))
        return made

    class FakeUnixSocket:
        def __init__(self, family, kind):
            assert family == socket.AF_UNIX
            assert kind == socket.SOCK_STREAM
            self.connected = None

        def connect(self, path):
            self.connected = path

    unix_socket = FakeUnixSocket(socket.AF_UNIX, socket.SOCK_STREAM)
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    unix_calls: list[tuple[object, object]] = []

    def fake_socket(family, kind):
        unix_calls.append((family, kind))
        return unix_socket

    monkeypatch.setattr(socket, "socket", fake_socket)

    tcp_client = Client.connect_tcp("host", 564, timeout=1.5, msize=123)
    assert tcp_client.transport is made
    assert tcp_client.msize == 123
    assert Client.connect_tcp("host", 564).msize == 8192
    assert tcp_calls == [(("host", 564), 1.5), (("host", 564), None)]
    unix_client = Client.connect_unix("/tmp/9p", msize=456)
    assert unix_client.transport is unix_socket
    assert unix_client.msize == 456
    assert unix_socket.connected == "/tmp/9p"
    assert Client.connect_unix("/tmp/9p").msize == 8192
    assert unix_calls == [
        (socket.AF_UNIX, socket.SOCK_STREAM),
        (socket.AF_UNIX, socket.SOCK_STREAM),
    ]


def test_client_defaults_are_explicit():
    transport = object()
    client = Client(transport)  # type: ignore[arg-type]
    assert client.transport is transport
    assert client.msize == 8192
    assert client.version_string == "9P2000"
    assert client._next_tag == 0
    assert client._closed is False
    assert client._reading is False


def test_rpc_assigns_tag_and_uses_client_msize(monkeypatch):
    written: list[object] = []
    max_sizes: list[int] = []
    transport = object()

    def fake_write(sent_transport, message):
        assert sent_transport is transport
        written.append(message)
        return 0

    def fake_read(sent_transport, *, max_size):
        assert sent_transport is transport
        max_sizes.append(max_size)
        return Rread(data=b"ok", tag=0)

    monkeypatch.setattr(client_mod, "write_message", fake_write)
    monkeypatch.setattr(client_mod, "read_message", fake_read)

    client = Client(transport, msize=1234)  # type: ignore[arg-type]
    assert client.rpc(Tread(fid=9, count=2, tag=99), Rread) == Rread(data=b"ok", tag=0)
    assert written == [Tread(fid=9, count=2, tag=0)]
    assert max_sizes == [1234]
    assert client._next_tag == 1


def test_rpc_keeps_tversion_notag_and_does_not_consume_tag(monkeypatch):
    written: list[object] = []

    monkeypatch.setattr(client_mod, "write_message", lambda _transport, message: written.append(message))
    monkeypatch.setattr(
        client_mod,
        "read_message",
        lambda _transport, *, max_size: Rversion(msize=max_size, version="9P2000", tag=NOTAG),
    )

    client = Client(object(), msize=4096)  # type: ignore[arg-type]
    assert client.rpc(Tversion(msize=4096), Rversion) == Rversion(msize=4096, tag=NOTAG)
    assert written == [Tversion(msize=4096)]
    assert client._next_tag == 0


def test_rpc_rejects_tag_mismatch_and_wrong_response_type(monkeypatch):
    monkeypatch.setattr(client_mod, "write_message", lambda _transport, _message: 0)

    client = Client(object())  # type: ignore[arg-type]
    monkeypatch.setattr(client_mod, "read_message", lambda _transport, *, max_size: Rread(data=b"", tag=2))
    with pytest.raises(ProtocolError, match="reply tag 2 did not match any outstanding request"):
        client.rpc(Tread(fid=1, count=1), Rread)

    client = Client(object())  # type: ignore[arg-type]
    monkeypatch.setattr(client_mod, "read_message", lambda _transport, *, max_size: Rclunk(tag=0))
    with pytest.raises(ProtocolError, match="expected Rread, got Rclunk"):
        client.rpc(Tread(fid=1, count=1), Rread)


def test_rpc_accepts_explicit_tag_override(monkeypatch):
    written: list[object] = []

    monkeypatch.setattr(client_mod, "write_message", lambda _transport, message: written.append(message))
    monkeypatch.setattr(
        client_mod,
        "read_message",
        lambda _transport, *, max_size: Rread(data=b"ok", tag=5),
    )

    client = Client(object())  # type: ignore[arg-type]
    assert client.rpc(Tread(fid=9, count=2), Rread, tag=5) == Rread(data=b"ok", tag=5)
    assert written == [Tread(fid=9, count=2, tag=5)]
    assert client._next_tag == 0


def test_rpc_accepts_explicit_tversion_tag_override(monkeypatch):
    written: list[object] = []

    monkeypatch.setattr(client_mod, "write_message", lambda _transport, message: written.append(message))
    monkeypatch.setattr(
        client_mod,
        "read_message",
        lambda _transport, *, max_size: Rversion(msize=max_size, version="9P2000", tag=5),
    )

    client = Client(object(), msize=4096)  # type: ignore[arg-type]
    assert client.rpc(Tversion(msize=4096), Rversion, tag=5) == Rversion(msize=4096, tag=5)
    assert written == [Tversion(msize=4096, tag=5)]
    assert client._next_tag == 0


def test_explicit_tag_validation_boundaries():
    assert Client._check_tag(0) == 0
    assert Client._check_tag(NOTAG) == NOTAG
    with pytest.raises(ValueError, match="tag must be in range"):
        Client._check_tag(-1)
    with pytest.raises(ValueError, match="tag must be in range"):
        Client._check_tag(NOTAG + 1)


def test_rpc_rejects_duplicate_and_notag_explicit_tags(monkeypatch):
    writes: list[object] = []
    monkeypatch.setattr(client_mod, "write_message", lambda _transport, message: writes.append(message))

    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(5)
    with pytest.raises(ProtocolError, match="already outstanding"):
        client.rpc(Tread(fid=1, count=1), Rread, tag=5)
    with pytest.raises(ProtocolError, match="non-version RPC cannot use NOTAG"):
        client.rpc(Tread(fid=1, count=1), Rread, tag=NOTAG)
    assert writes == []


def test_rpc_cleans_outstanding_when_write_fails(monkeypatch):
    error = BrokenPipeError("gone")

    def fail_write(_transport, _message):
        raise error

    monkeypatch.setattr(client_mod, "write_message", fail_write)

    client = Client(object())  # type: ignore[arg-type]
    with pytest.raises(BrokenPipeError) as exc:
        client.rpc(Tread(fid=1, count=1), Rread)
    assert exc.value is error
    assert client._outstanding == set()
    assert client._pending == {}


def test_forget_outstanding_removes_stale_pending_reply():
    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(7)
    client._pending[7] = Rread(data=b"stale", tag=7)

    client._forget_outstanding(7)

    assert 7 not in client._outstanding
    assert 7 not in client._pending


def test_wait_for_reply_cleans_outstanding_after_close():
    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(4)
    client.close()
    with pytest.raises(ProtocolError, match="client is closed"):
        client._wait_for_reply(4)
    assert 4 not in client._outstanding


def test_wait_for_reply_cleans_outstanding_after_connection_error():
    error = OSError("lost")
    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(4)
    client._connection_error = error

    with pytest.raises(ProtocolError, match="client connection failed") as exc:
        client._wait_for_reply(4)
    assert exc.value.__cause__ is error
    assert 4 not in client._outstanding


def test_wait_for_reply_read_failure_marks_connection_failed(monkeypatch):
    error = EOFError("lost")
    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(4)
    monkeypatch.setattr(client_mod, "read_message", lambda _transport, *, max_size: (_ for _ in ()).throw(error))

    with pytest.raises(EOFError) as exc:
        client._wait_for_reply(4)
    assert exc.value is error
    assert client._connection_error is error
    assert client._outstanding == set()
    assert client._pending == {}
    assert client._reading is False


def test_wait_for_reply_rejects_unexpected_reply_without_extra_reads(monkeypatch):
    calls = 0

    def fake_read(_transport, *, max_size):
        nonlocal calls
        calls += 1
        return Rread(data=b"", tag=2)

    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(0)
    monkeypatch.setattr(client_mod, "read_message", fake_read)

    with pytest.raises(ProtocolError, match="did not match any outstanding request") as exc:
        client._wait_for_reply(0)
    assert calls == 1
    assert client._connection_error is exc.value


def test_wait_for_reply_rejects_duplicate_pending_reply(monkeypatch):
    def fake_read(_transport, *, max_size):
        return Rread(data=b"new", tag=2)

    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.update({0, 2})
    client._pending[2] = Rread(data=b"old", tag=2)
    monkeypatch.setattr(client_mod, "read_message", fake_read)

    with pytest.raises(ProtocolError, match="did not match any outstanding request"):
        client._wait_for_reply(0)


def test_wait_for_reply_starts_idle_reader_promptly(monkeypatch):
    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.add(0)
    expected = Rread(data=b"ok", tag=0)
    monkeypatch.setattr(client_mod, "read_message", lambda _transport, *, max_size: expected)
    result: list[object] = []
    errors: list[object] = []

    def wait() -> None:
        try:
            result.append(client._wait_for_reply(0))
        except (EOFError, OSError, ProtocolError) as exc:
            errors.append(exc)

    thread = threading.Thread(target=wait, daemon=True)
    thread.start()
    thread.join(timeout=0.5)

    assert not thread.is_alive()
    assert errors == []
    assert result == [expected]
    assert client._reading is False


def test_wait_for_reply_serializes_active_reader(monkeypatch):
    client = Client(object())  # type: ignore[arg-type]
    client._outstanding.update({0, 1})
    first_read_entered = threading.Event()
    release_first_read = threading.Event()
    call_lock = threading.Lock()
    calls = 0

    def fake_read(_transport, *, max_size):
        nonlocal calls
        with call_lock:
            calls += 1
            call = calls
        if call == 1:
            first_read_entered.set()
            assert release_first_read.wait(timeout=1)
            return Rread(data=b"zero", tag=0)
        if call == 2:
            return Rread(data=b"one", tag=1)
        raise AssertionError("only one waiter may own the transport reader")

    monkeypatch.setattr(client_mod, "read_message", fake_read)
    results: list[object] = []
    errors: list[BaseException] = []

    def wait(tag: int) -> None:
        try:
            results.append(client._wait_for_reply(tag))
        except (AssertionError, EOFError, OSError, ProtocolError) as exc:
            errors.append(exc)

    first = threading.Thread(target=wait, args=(0,), daemon=True)
    second = threading.Thread(target=wait, args=(1,), daemon=True)
    first.start()
    assert first_read_entered.wait(timeout=1)
    second.start()

    try:
        time.sleep(0.05)
        with call_lock:
            assert calls == 1
    finally:
        release_first_read.set()

    first.join(timeout=1)
    second.join(timeout=1)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert sorted((reply.tag, reply.data) for reply in results if isinstance(reply, Rread)) == [
        (0, b"zero"),
        (1, b"one"),
    ]


def test_helper_methods_send_exact_requests_and_expected_types(monkeypatch):
    client = Client(object(), msize=64, version="9P2000.u")  # type: ignore[arg-type]
    stat_entry = Dir(qid=Qid(path=10), name="n", uid="u", gid="g", muid="m")
    calls: list[tuple[object, object]] = []
    replies = [
        Rversion(msize=32, version="9P2000"),
        Rattach(qid=Qid(path=1)),
        Rwalk(wqid=(Qid(path=2),)),
        Ropen(qid=Qid(path=3), iounit=11),
        Rcreate(qid=Qid(path=4), iounit=12),
        Rread(data=b"data"),
        Rread(data=b"default"),
        Rwrite(count=4),
        Rclunk(),
        Rremove(),
        Rstat(stat=stat_entry),
        Rwstat(),
    ]

    def fake_rpc(request, expect):
        calls.append((request, expect))
        return replies.pop(0)

    client.rpc = fake_rpc  # type: ignore[method-assign]

    assert client.negotiate() == Rversion(msize=32, version="9P2000")
    assert client.msize == 32
    assert client.version_string == "9P2000"
    assert client.attach(fid=5, uname="u", aname="a", afid=7) == Qid(path=1)
    assert client.walk(5, 6, ("a", "b")) == (Qid(path=2),)
    assert client.open(6, mode=2) == (Qid(path=3), 11)
    assert client.create(6, "new", 0o644, mode=1) == (Qid(path=4), 12)
    assert client.read(6, count=4, offset=9) == b"data"
    assert client.read(6) == b"default"
    assert client.write(6, b"data", offset=13) == 4
    client.clunk(6)
    client.remove(6)
    assert client.stat(6) == stat_entry
    client.wstat(6, stat_entry)

    assert calls == [
        (Tversion(msize=64, version="9P2000.u"), Rversion),
        (Tattach(fid=5, afid=7, uname="u", aname="a"), Rattach),
        (Twalk(fid=5, newfid=6, wname=("a", "b")), Rwalk),
        (Topen(fid=6, mode=2), Ropen),
        (Tcreate(fid=6, name="new", perm=0o644, mode=1), Rcreate),
        (Tread(fid=6, offset=9, count=4), Rread),
        (Tread(fid=6, offset=0, count=max(0, 32 - IOHDRSZ)), Rread),
        (Twrite(fid=6, offset=13, data=b"data"), Rwrite),
        (Tclunk(fid=6), Rclunk),
        (Tremove(fid=6), Rremove),
        (Tstat(fid=6), Rstat),
        (Twstat(fid=6, stat=stat_entry), Rwstat),
    ]


def test_helper_methods_reject_unexpected_response_types(monkeypatch):
    cases = [
        (lambda client: client.negotiate(), Rerror(ename="wrong")),
        (lambda client: client.attach(fid=1, uname="u"), Rclunk()),
        (lambda client: client.walk(1, 2, "a"), Rclunk()),
        (lambda client: client.open(1), Rclunk()),
        (lambda client: client.create(1, "n", 0o644), Rclunk()),
        (lambda client: client.read(1, count=1), Rclunk()),
        (lambda client: client.write(1, b"x"), Rclunk()),
        (lambda client: client.clunk(1), Rread(data=b"")),
        (lambda client: client.remove(1), Rread(data=b"")),
        (lambda client: client.stat(1), Rclunk()),
        (lambda client: client.wstat(1, Dir()), Rread(data=b"")),
    ]

    monkeypatch.setattr(client_mod, "write_message", lambda _transport, _message: 0)
    for call, response in cases:
        client = Client(object())  # type: ignore[arg-type]
        monkeypatch.setattr(
            client_mod,
            "read_message",
            lambda _transport, *, max_size, response=response: response,
        )
        with pytest.raises(ProtocolError):
            call(client)


def test_path_names_accepts_iterables_without_string_filtering():
    assert Client._path_names([".", "", "a"]) == (".", "", "a")


def test_stat_decodes_raw_stat_bytes(monkeypatch):
    decoded = Dir(qid=Qid(path=99), name="decoded", uid="u", gid="g", muid="m")
    calls: list[object] = []
    client = Client(object())  # type: ignore[arg-type]

    def fake_rpc(request, expect):
        calls.append((request, expect))
        return Rstat(stat=b"raw-stat")

    monkeypatch.setattr(client_mod, "decode_dir", lambda data: decoded if data == b"raw-stat" else None)
    client.rpc = fake_rpc  # type: ignore[method-assign]

    assert client.stat(42) == decoded
    assert calls == [(Tstat(fid=42), Rstat)]


def test_helper_defaults_are_exact(monkeypatch):
    client = Client(object(), msize=IOHDRSZ - 1)  # type: ignore[arg-type]
    calls: list[tuple[object, object]] = []
    replies = [
        Rattach(qid=Qid(path=1)),
        Rread(data=b""),
        Rwrite(count=0),
    ]

    def fake_rpc(request, expect):
        calls.append((request, expect))
        return replies.pop(0)

    monkeypatch.setattr(client_mod.getpass, "getuser", lambda: "me")
    client.rpc = fake_rpc  # type: ignore[method-assign]

    assert client.attach() == Qid(path=1)
    assert client.read(fid=9) == b""
    assert client.write(fid=9, data=b"") == 0
    assert Client._path_names("./a/./") == ("a",)
    assert calls == [
        (Tattach(fid=0, afid=NOFID, uname="me", aname=""), Rattach),
        (Tread(fid=9, offset=0, count=0), Rread),
        (Twrite(fid=9, offset=0, data=b""), Rwrite),
    ]
