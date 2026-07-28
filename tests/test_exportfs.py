from __future__ import annotations

import subprocess
from os import PathLike
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

import py9p.exportfs as exportfs_mod
from py9p import Client, ExportFSConfig
from py9p.exportfs import ProcessTransport

argv_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
)


@given(drawterm=argv_text, root=st.one_of(st.none(), argv_text))
def test_exportfs_config_preserves_arguments_as_argv(drawterm: str, root: str | None):
    argv = ExportFSConfig(drawterm=drawterm, root=root).argv()

    assert argv[0] == drawterm
    assert argv[1] == "-9"
    if root is None:
        assert argv == [drawterm, "-9"]
    else:
        assert argv == [drawterm, "-9", "-r", root]
    assert all("\x00" not in arg for arg in argv)


@given(drawterm=argv_text, root=argv_text)
def test_exportfs_config_keeps_shell_characters_literal(drawterm: str, root: str):
    argv = ExportFSConfig(drawterm=drawterm, root=root).argv()

    assert len(argv) == 4
    assert argv[0] == drawterm
    assert argv[3] == root


class FakeStream:
    def __init__(self, data: bytes = b""):
        self.data = bytearray(data)
        self.writes: list[bytes] = []
        self.closed = 0
        self.flushed = 0

    def read(self, size: int) -> bytes:
        chunk = bytes(self.data[:size])
        del self.data[:size]
        return chunk

    def write(self, data: bytes) -> int:
        self.writes.append(bytes(data))
        return len(data)

    def flush(self) -> None:
        self.flushed += 1

    def close(self) -> None:
        self.closed += 1


class FakeProcess:
    def __init__(self):
        self.stdin = FakeStream()
        self.stdout = FakeStream(b"abcdef")
        self.terminated = 0
        self.killed = 0
        self.waits: list[float | None] = []
        self.running = True

    def poll(self) -> int | None:
        return None if self.running else 0

    def terminate(self) -> None:
        self.terminated += 1

    def kill(self) -> None:
        self.killed += 1
        self.running = False

    def wait(self, timeout: float | None = None) -> int:
        self.waits.append(timeout)
        self.running = False
        return 0


def test_process_transport_reads_writes_flushes_and_terminates():
    process = FakeProcess()
    transport = ProcessTransport(process, terminate_timeout=0.25)  # type: ignore[arg-type]

    assert transport.read(2) == b"ab"
    assert transport.write(b"hello") == 5
    transport.flush()
    transport.close()
    transport.close()

    assert process.stdin.writes == [b"hello"]
    assert process.stdin.flushed == 1
    assert process.stdin.closed == 1
    assert process.stdout.closed == 1
    assert process.terminated == 1
    assert process.killed == 0
    assert process.waits == [0.25]


def test_process_transport_defaults_to_one_second_terminate_timeout():
    process = FakeProcess()
    transport = ProcessTransport(process)  # type: ignore[arg-type]

    assert transport._closed is False
    transport.close()

    assert process.waits == [1.0]


def test_process_transport_requires_both_pipes():
    process = FakeProcess()
    process.stdin = None
    with pytest.raises(ValueError):
        ProcessTransport(process)  # type: ignore[arg-type]

    process = FakeProcess()
    process.stdout = None
    with pytest.raises(ValueError):
        ProcessTransport(process)  # type: ignore[arg-type]


@pytest.mark.parametrize("exc_type", [OSError, ValueError])
def test_process_transport_suppresses_stream_close_errors(exc_type: type[Exception]):
    class RaisingStream(FakeStream):
        def close(self) -> None:
            self.closed += 1
            raise exc_type("already closed")

    process = FakeProcess()
    process.stdin = RaisingStream()
    process.stdout = RaisingStream()
    transport = ProcessTransport(process, terminate_timeout=0.125)  # type: ignore[arg-type]

    transport.close()

    assert process.stdin.closed == 1
    assert process.stdout.closed == 1
    assert process.terminated == 1
    assert process.waits == [0.125]


def test_process_transport_kills_child_when_terminate_times_out():
    class TimeoutProcess(FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            self.waits.append(timeout)
            if self.killed == 0:
                raise subprocess.TimeoutExpired("drawterm", timeout)
            self.running = False
            return 0

    process = TimeoutProcess()
    transport = ProcessTransport(process, terminate_timeout=0.5)  # type: ignore[arg-type]
    transport.close()

    assert process.terminated == 1
    assert process.killed == 1
    assert process.waits == [0.5, 0.5]


def test_exportfs_transport_starts_drawterm_without_shell(monkeypatch):
    started: list[tuple[list[str], dict[str, Any]]] = []

    class FakePopen(FakeProcess):
        def __init__(self, argv: list[str], **kwargs: Any):
            super().__init__()
            started.append((argv, kwargs))

    monkeypatch.setattr(exportfs_mod.subprocess, "Popen", FakePopen)

    transport = exportfs_mod.exportfs_transport(
        drawterm="/tmp/draw term",
        root="/tmp/root path",
        stderr=None,
        terminate_timeout=0.75,
    )

    assert isinstance(transport, ProcessTransport)
    assert started == [
        (
            ["/tmp/draw term", "-9", "-r", "/tmp/root path"],
            {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": None},
        )
    ]
    assert "shell" not in started[0][1]
    assert transport._terminate_timeout == 0.75


def test_exportfs_transport_uses_defaults_and_custom_stderr(monkeypatch):
    started: list[tuple[list[str], dict[str, Any]]] = []
    stderr = object()

    class FakePopen(FakeProcess):
        def __init__(self, argv: list[str], **kwargs: Any):
            super().__init__()
            started.append((argv, kwargs))

    monkeypatch.setattr(exportfs_mod.subprocess, "Popen", FakePopen)

    transport = exportfs_mod.exportfs_transport(stderr=stderr)  # type: ignore[arg-type]

    assert transport._terminate_timeout == 1.0
    assert started == [
        (
            ["drawterm", "-9"],
            {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": stderr},
        )
    ]


def test_client_connect_exportfs_uses_exportfs_transport(monkeypatch):
    calls: list[tuple[str, str | PathLike[str] | None]] = []
    transport = FakeStream()

    def fake_exportfs_transport(*, drawterm, root):
        calls.append((drawterm, root))
        return transport

    monkeypatch.setattr(exportfs_mod, "exportfs_transport", fake_exportfs_transport)

    client = Client.connect_exportfs(
        drawterm="dt",
        root="root",
        msize=4096,
        version="9P2000.TEST",
    )

    assert client.transport is transport
    assert client.msize == 4096
    assert client.version_string == "9P2000.TEST"
    assert calls == [("dt", "root")]


def test_client_connect_exportfs_uses_public_defaults(monkeypatch):
    calls: list[tuple[str, str | PathLike[str] | None]] = []
    transport = FakeStream()

    def fake_exportfs_transport(*, drawterm, root):
        calls.append((drawterm, root))
        return transport

    monkeypatch.setattr(exportfs_mod, "exportfs_transport", fake_exportfs_transport)

    client = Client.connect_exportfs()

    assert client.transport is transport
    assert client.msize == 8192
    assert client.version_string == "9P2000"
    assert calls == [("drawterm", None)]
