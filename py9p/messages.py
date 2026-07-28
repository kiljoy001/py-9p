"""Pythonic 9P2000 message and stat dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from .constants import (
    MAXWELEM,
    NOFID,
    NOTAG,
    VERSION9P,
    MessageType,
)


class NinePError(RuntimeError):
    """Base exception for py9p errors."""


class CodecError(NinePError):
    """Raised when a 9P message or stat buffer cannot be encoded/decoded."""


class ProtocolError(NinePError):
    """Raised when a peer sends an unexpected or invalid protocol message."""


@dataclass(frozen=True, slots=True)
class Qid:
    type: int = 0
    vers: int = 0
    path: int = 0


@dataclass(frozen=True, slots=True)
class Dir:
    type: int = 0
    dev: int = 0
    qid: Qid = field(default_factory=Qid)
    mode: int = 0
    atime: int = 0
    mtime: int = 0
    length: int = 0
    name: str = ""
    uid: str = ""
    gid: str = ""
    muid: str = ""

    def to_bytes(self) -> bytes:
        from .native import encode_dir

        return encode_dir(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> Dir:
        from .native import decode_dir

        return decode_dir(data)


class Message:
    """Base class for concrete 9P2000 messages."""

    message_type: ClassVar[MessageType]
    tag: int

    def to_bytes(self) -> bytes:
        from .native import encode_message

        return encode_message(self)

    @property
    def type(self) -> MessageType:
        return self.message_type


@dataclass(frozen=True, slots=True)
class Tversion(Message):
    msize: int = 8192
    version: str = VERSION9P
    tag: int = NOTAG
    message_type: ClassVar[MessageType] = MessageType.TVERSION


@dataclass(frozen=True, slots=True)
class Rversion(Message):
    msize: int
    version: str = VERSION9P
    tag: int = NOTAG
    message_type: ClassVar[MessageType] = MessageType.RVERSION


@dataclass(frozen=True, slots=True)
class Tauth(Message):
    afid: int
    uname: str
    aname: str = ""
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TAUTH


@dataclass(frozen=True, slots=True)
class Rauth(Message):
    aqid: Qid
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RAUTH


@dataclass(frozen=True, slots=True)
class Tattach(Message):
    fid: int
    uname: str
    afid: int = NOFID
    aname: str = ""
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TATTACH


@dataclass(frozen=True, slots=True)
class Rattach(Message):
    qid: Qid
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RATTACH


@dataclass(frozen=True, slots=True)
class Rerror(Message):
    ename: str
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RERROR


@dataclass(frozen=True, slots=True)
class Tflush(Message):
    oldtag: int
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TFLUSH


@dataclass(frozen=True, slots=True)
class Rflush(Message):
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RFLUSH


@dataclass(frozen=True, slots=True)
class Twalk(Message):
    fid: int
    newfid: int
    wname: tuple[str, ...] = ()
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TWALK

    def __post_init__(self) -> None:
        object.__setattr__(self, "wname", tuple(self.wname))
        if len(self.wname) > MAXWELEM:
            raise ValueError(f"Twalk accepts at most {MAXWELEM} path elements")  # pragma: no mutate


@dataclass(frozen=True, slots=True)
class Rwalk(Message):
    wqid: tuple[Qid, ...] = ()
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RWALK

    def __post_init__(self) -> None:
        object.__setattr__(self, "wqid", tuple(self.wqid))
        if len(self.wqid) > MAXWELEM:
            raise ValueError(f"Rwalk accepts at most {MAXWELEM} qids")  # pragma: no mutate


@dataclass(frozen=True, slots=True)
class Topen(Message):
    fid: int
    mode: int = 0
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TOPEN


@dataclass(frozen=True, slots=True)
class Ropen(Message):
    qid: Qid
    iounit: int = 0
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.ROPEN


@dataclass(frozen=True, slots=True)
class Tcreate(Message):
    fid: int
    name: str
    perm: int
    mode: int = 0
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TCREATE


@dataclass(frozen=True, slots=True)
class Rcreate(Message):
    qid: Qid
    iounit: int = 0
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RCREATE


@dataclass(frozen=True, slots=True)
class Tread(Message):
    fid: int
    offset: int = 0
    count: int = 0
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TREAD


@dataclass(frozen=True, slots=True)
class Rread(Message):
    data: bytes = b""
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RREAD


@dataclass(frozen=True, slots=True)
class Twrite(Message):
    fid: int
    data: bytes
    offset: int = 0
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TWRITE


@dataclass(frozen=True, slots=True)
class Rwrite(Message):
    count: int
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RWRITE


@dataclass(frozen=True, slots=True)
class Tclunk(Message):
    fid: int
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TCLUNK


@dataclass(frozen=True, slots=True)
class Rclunk(Message):
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RCLUNK


@dataclass(frozen=True, slots=True)
class Tremove(Message):
    fid: int
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TREMOVE


@dataclass(frozen=True, slots=True)
class Rremove(Message):
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RREMOVE


@dataclass(frozen=True, slots=True)
class Tstat(Message):
    fid: int
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TSTAT


@dataclass(frozen=True, slots=True)
class Rstat(Message):
    stat: Dir | bytes
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RSTAT


@dataclass(frozen=True, slots=True)
class Twstat(Message):
    fid: int
    stat: Dir | bytes
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.TWSTAT


@dataclass(frozen=True, slots=True)
class Rwstat(Message):
    tag: int = 0
    message_type: ClassVar[MessageType] = MessageType.RWSTAT


MESSAGE_CLASSES: dict[MessageType, type[Message]] = {
    cls.message_type: cls
    for cls in (
        Tversion,
        Rversion,
        Tauth,
        Rauth,
        Tattach,
        Rattach,
        Rerror,
        Tflush,
        Rflush,
        Twalk,
        Rwalk,
        Topen,
        Ropen,
        Tcreate,
        Rcreate,
        Tread,
        Rread,
        Twrite,
        Rwrite,
        Tclunk,
        Rclunk,
        Tremove,
        Rremove,
        Tstat,
        Rstat,
        Twstat,
        Rwstat,
    )
}


def decode_message(data: bytes) -> Message:
    from .native import decode_message as native_decode_message

    return native_decode_message(data)
