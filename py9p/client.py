"""Synchronous multiplexed 9P2000 client built on py9p message objects."""

from __future__ import annotations

import getpass
import os
import socket
import threading
from collections.abc import Iterable
from dataclasses import replace
from os import PathLike
from typing import BinaryIO, TypeVar, overload

from .constants import IOHDRSZ, NOFID, NOTAG, OREAD, VERSION9P
from .io import read_message, write_message
from .messages import (
    Dir,
    Message,
    ProtocolError,
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
)
from .native import decode_dir


class RemoteError(ProtocolError):
    """Raised when the 9P server replies with Rerror."""


_TMessage = TypeVar("_TMessage", bound=Message)


class Client:
    """Synchronous multiplexed 9P2000 client.

    Concurrent callers may share one client. Requests are tagged by default,
    writes are serialized, and replies are dispatched back to the caller that
    owns the matching tag.
    """

    def __init__(
        self,
        transport: BinaryIO | socket.socket,
        *,
        msize: int = 8192,
        version: str = VERSION9P,
    ):
        self.transport = transport
        self.msize = msize
        self.version_string = version
        self._next_tag = 0
        self._closed = False
        self._write_lock = threading.Lock()
        self._mux = threading.Condition()
        self._pending: dict[int, Message] = {}
        self._outstanding: set[int] = set()
        self._reading = False
        self._connection_error: BaseException | None = None

    @classmethod
    def connect_tcp(
        cls,
        host: str,
        port: int,
        *,
        timeout: float | None = None,
        msize: int = 8192,
    ) -> Client:
        sock = socket.create_connection((host, port), timeout=timeout)
        return cls(sock, msize=msize)

    @classmethod
    def connect_unix(cls, path: str, *, msize: int = 8192) -> Client:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        return cls(sock, msize=msize)

    @classmethod
    def connect_exportfs(
        cls,
        *,
        drawterm: str | PathLike[str] = "drawterm",
        root: str | PathLike[str] | None = None,
        msize: int = 8192,
        version: str = VERSION9P,
    ) -> Client:
        from .exportfs import exportfs_transport

        transport = exportfs_transport(drawterm=os.fspath(drawterm), root=root)
        return cls(transport, msize=msize, version=version)

    def close(self) -> None:
        should_close = False  # pragma: no mutate
        with self._mux:
            if not self._closed:
                self._closed = True
                should_close = True
                self._mux.notify_all()
        if should_close:
            close = getattr(self.transport, "close", None)
            if close is not None:
                close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _tag(self) -> int:
        with self._mux:
            return self._tag_locked()

    def _tag_locked(self) -> int:
        tag = self._next_tag
        self._next_tag = (self._next_tag + 1) & 0xFFFF
        if self._next_tag == NOTAG:
            self._next_tag = 0
        return tag

    def _allocate_tag_locked(self) -> int:
        for _ in range(NOTAG):
            tag = self._tag_locked()
            if tag not in self._outstanding:
                return tag
        raise ProtocolError("all 9P tags are in use")  # pragma: no mutate

    @overload
    def rpc(self, request: Message, expect: type[_TMessage], *, tag: int | None = None) -> _TMessage: ...

    @overload
    def rpc(
        self,
        request: Message,
        expect: tuple[type[Message], ...],
        *,
        tag: int | None = None,
    ) -> Message: ...

    @overload
    def rpc(self, request: Message, expect: None = None, *, tag: int | None = None) -> Message: ...

    def rpc(
        self,
        request: Message,
        expect: type[Message] | tuple[type[Message], ...] | None = None,
        *,
        tag: int | None = None,
    ) -> Message:
        request = self._prepare_request(request, tag)
        try:
            with self._write_lock:
                write_message(self.transport, request)
        except BaseException:
            self._forget_outstanding(request.tag)
            raise

        response = self._wait_for_reply(request.tag)
        if isinstance(response, Rerror):
            raise RemoteError(response.ename)
        if expect is not None and not isinstance(response, expect):
            raise ProtocolError(f"expected {self._type_name(expect)}, got {type(response).__name__}")  # pragma: no mutate
        return response

    def _prepare_request(self, request: Message, tag: int | None) -> Message:
        with self._mux:
            if self._closed:
                raise ProtocolError("client is closed")  # pragma: no mutate
            if self._connection_error is not None:
                raise ProtocolError("client connection failed") from self._connection_error  # pragma: no mutate
            if isinstance(request, Tversion):
                if self._outstanding:
                    raise ProtocolError("Tversion requires no outstanding RPCs")  # pragma: no mutate
                request_tag = request.tag if tag is None else self._check_tag(tag)
                if tag is not None:
                    request = replace(request, tag=request_tag)
            else:
                if NOTAG in self._outstanding:
                    raise ProtocolError("Tversion is still outstanding")  # pragma: no mutate
                request_tag = self._allocate_tag_locked() if tag is None else self._check_tag(tag)
                if request_tag == NOTAG:
                    raise ProtocolError("non-version RPC cannot use NOTAG")  # pragma: no mutate
                request = replace(request, tag=request_tag)
            if request_tag in self._outstanding:
                raise ProtocolError(f"tag {request_tag} is already outstanding")  # pragma: no mutate
            self._outstanding.add(request_tag)
            return request

    @staticmethod
    def _check_tag(tag: int) -> int:
        if not 0 <= tag <= NOTAG:
            raise ValueError("tag must be in range 0..65535")  # pragma: no mutate
        return tag

    def _forget_outstanding(self, tag: int) -> None:
        with self._mux:
            self._outstanding.discard(tag)
            self._pending.pop(tag, None)
            self._mux.notify_all()

    def _fail_connection(self, exc: BaseException) -> None:
        with self._mux:
            self._connection_error = exc
            self._pending.clear()
            self._outstanding.clear()
            self._reading = False
            self._mux.notify_all()

    def _wait_for_reply(self, tag: int) -> Message:
        while True:
            with self._mux:
                if tag in self._pending:
                    response = self._pending.pop(tag)
                    self._outstanding.discard(tag)
                    self._mux.notify_all()
                    return response
                if self._closed:
                    self._outstanding.discard(tag)
                    self._mux.notify_all()
                    raise ProtocolError("client is closed")  # pragma: no mutate
                if self._connection_error is not None:
                    self._outstanding.discard(tag)
                    self._mux.notify_all()
                    raise ProtocolError("client connection failed") from self._connection_error  # pragma: no mutate
                if not self._reading:  # pragma: no mutate
                    self._reading = True
                    should_read = True  # pragma: no mutate
                else:
                    should_read = False  # pragma: no mutate
                    self._mux.wait()
            if not should_read:  # pragma: no mutate
                continue

            try:
                response = read_message(self.transport, max_size=self.msize)
            except BaseException as exc:
                self._fail_connection(exc)
                raise

            with self._mux:
                self._reading = False
                if response.tag not in self._outstanding or response.tag in self._pending:  # pragma: no mutate
                    err = ProtocolError(
                        f"reply tag {response.tag} did not match any outstanding request"
                    )
                    self._connection_error = err
                    self._pending.clear()
                    self._outstanding.clear()
                    self._mux.notify_all()
                    raise err
                self._pending[response.tag] = response
                self._mux.notify_all()

    @staticmethod
    def _type_name(expect: type[Message] | tuple[type[Message], ...]) -> str:
        if isinstance(expect, tuple):
            return " or ".join(t.__name__ for t in expect)
        return expect.__name__

    def negotiate(self) -> Rversion:
        response = self.rpc(
            Tversion(msize=self.msize, version=self.version_string),
            Rversion,
        )
        self.msize = min(self.msize, response.msize)
        self.version_string = response.version
        return response

    def attach(
        self,
        fid: int = 0,
        *,
        uname: str | None = None,
        aname: str = "",
        afid: int = NOFID,
    ) -> Qid:
        response = self.rpc(
            Tattach(fid=fid, afid=afid, uname=uname or getpass.getuser(), aname=aname),
            Rattach,
        )
        return response.qid

    def walk(self, fid: int, newfid: int, path: str | Iterable[str]) -> tuple[Qid, ...]:
        names = self._path_names(path)
        response = self.rpc(Twalk(fid=fid, newfid=newfid, wname=names), Rwalk)
        return response.wqid

    @staticmethod
    def _path_names(path: str | Iterable[str]) -> tuple[str, ...]:
        if isinstance(path, str):
            return tuple(part for part in path.split("/") if part and part != ".")
        return tuple(path)

    def open(self, fid: int, mode: int = int(OREAD)) -> tuple[Qid, int]:
        response = self.rpc(Topen(fid=fid, mode=mode), Ropen)
        return response.qid, response.iounit

    def create(self, fid: int, name: str, perm: int, mode: int = int(OREAD)) -> tuple[Qid, int]:
        response = self.rpc(Tcreate(fid=fid, name=name, perm=perm, mode=mode), Rcreate)
        return response.qid, response.iounit

    def read(self, fid: int, count: int | None = None, offset: int = 0) -> bytes:
        if count is None:
            count = max(0, self.msize - IOHDRSZ)
        response = self.rpc(Tread(fid=fid, offset=offset, count=count), Rread)
        return response.data

    def write(self, fid: int, data: bytes, offset: int = 0) -> int:
        response = self.rpc(Twrite(fid=fid, offset=offset, data=data), Rwrite)
        return response.count

    def clunk(self, fid: int) -> None:
        self.rpc(Tclunk(fid=fid), Rclunk)

    def remove(self, fid: int) -> None:
        self.rpc(Tremove(fid=fid), Rremove)

    def stat(self, fid: int) -> Dir:
        response = self.rpc(Tstat(fid=fid), Rstat)
        if isinstance(response.stat, Dir):
            return response.stat
        return decode_dir(response.stat)

    def wstat(self, fid: int, stat: Dir | bytes) -> None:
        self.rpc(Twstat(fid=fid, stat=stat), Rwstat)
