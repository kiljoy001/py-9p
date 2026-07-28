"""Process transport helpers for drawterm/9front exportfs."""

from __future__ import annotations

import os
import subprocess  # nosec B404
from contextlib import suppress
from dataclasses import dataclass
from os import PathLike
from typing import BinaryIO


@dataclass(frozen=True, slots=True)
class ExportFSConfig:
    """Command-line shape for drawterm's stdio exportfs mode."""

    drawterm: str | PathLike[str] = "drawterm"
    root: str | PathLike[str] | None = None

    def argv(self) -> list[str]:
        argv = [os.fspath(self.drawterm), "-9"]
        if self.root is not None:
            argv.extend(("-r", os.fspath(self.root)))
        return argv


class ProcessTransport:
    """Binary transport that reads and writes a child process over pipes."""

    def __init__(self, process: subprocess.Popen[bytes], *, terminate_timeout: float = 1.0):
        if process.stdin is None or process.stdout is None:
            raise ValueError("process must be started with stdin=PIPE and stdout=PIPE")  # pragma: no mutate
        self.process = process
        self._stdin: BinaryIO = process.stdin
        self._stdout: BinaryIO = process.stdout
        self._terminate_timeout = terminate_timeout
        self._closed = False

    def read(self, size: int) -> bytes:
        return self._stdout.read(size)

    def write(self, data: bytes) -> int | None:
        return self._stdin.write(data)

    def flush(self) -> None:
        self._stdin.flush()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (self._stdin, self._stdout):
            with suppress(OSError, ValueError):
                stream.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=self._terminate_timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=self._terminate_timeout)


def exportfs_transport(
    *,
    drawterm: str | PathLike[str] = "drawterm",
    root: str | PathLike[str] | None = None,
    stderr: int | BinaryIO | None = subprocess.DEVNULL,
    terminate_timeout: float = 1.0,
) -> ProcessTransport:
    """Start drawterm's `-9` exportfs mode and return a 9P transport.

    This is intentionally a process wrapper, not a Python reimplementation of
    exportfs. Authenticated 9front sessions should reuse drawterm's auth/cpu
    path before handing the established fd to exportfs.
    """

    config = ExportFSConfig(drawterm=drawterm, root=root)
    process = subprocess.Popen(  # nosec B603
        config.argv(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr,
    )
    return ProcessTransport(process, terminate_timeout=terminate_timeout)
