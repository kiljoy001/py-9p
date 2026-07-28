"""ctypes binding to the vendored plan9port 9P2000 wire codec."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass, replace
from typing import Any

from .constants import MAXWELEM, MessageType
from .messages import (
    CodecError,
    Dir,
    Message,
    Qid,
    Rattach,
    Rauth,
    Rclunk,
    Rcreate,
    Rerror,
    Rflush,
    Ropen,
    Rread,
    Rremove,
    Rstat,
    Rversion,
    Rwalk,
    Rwrite,
    Rwstat,
    Tattach,
    Tauth,
    Tclunk,
    Tcreate,
    Tflush,
    Topen,
    Tread,
    Tremove,
    Tstat,
    Tversion,
    Twalk,
    Twrite,
    Twstat,
)


class NativeUnavailable(RuntimeError):
    """Raised when the bundled native library cannot be found."""


_U8P = ctypes.POINTER(ctypes.c_uint8)
_U32P = ctypes.POINTER(ctypes.c_uint32)


class _Py9pQid(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("vers", ctypes.c_uint32),
        ("path", ctypes.c_uint64),
    ]


class _Py9pDir(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint16),
        ("dev", ctypes.c_uint32),
        ("qid", _Py9pQid),
        ("mode", ctypes.c_uint32),
        ("atime", ctypes.c_uint32),
        ("mtime", ctypes.c_uint32),
        ("length", ctypes.c_int64),
        ("name", ctypes.c_char_p),
        ("uid", ctypes.c_char_p),
        ("gid", ctypes.c_char_p),
        ("muid", ctypes.c_char_p),
    ]


class _Py9pFcall(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("tag", ctypes.c_uint16),
        ("fid", ctypes.c_uint32),
        ("msize", ctypes.c_uint32),
        ("version", ctypes.c_char_p),
        ("oldtag", ctypes.c_uint16),
        ("ename", ctypes.c_char_p),
        ("qid", _Py9pQid),
        ("iounit", ctypes.c_uint32),
        ("aqid", _Py9pQid),
        ("afid", ctypes.c_uint32),
        ("uname", ctypes.c_char_p),
        ("aname", ctypes.c_char_p),
        ("perm", ctypes.c_uint32),
        ("name", ctypes.c_char_p),
        ("mode", ctypes.c_uint8),
        ("newfid", ctypes.c_uint32),
        ("nwname", ctypes.c_uint16),
        ("wname", ctypes.c_char_p * MAXWELEM),
        ("nwqid", ctypes.c_uint16),
        ("wqid", _Py9pQid * MAXWELEM),
        ("offset", ctypes.c_int64),
        ("count", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
        ("nstat", ctypes.c_uint16),
        ("stat", ctypes.c_void_p),
        ("unixfd", ctypes.c_int32),
        ("errornum", ctypes.c_int32),
        ("uidnum", ctypes.c_int32),
        ("extension", ctypes.c_char_p),
    ]


class _NonNullPointer:
    _base: Any
    _name = "pointer"

    @classmethod
    def from_param(cls, value: Any) -> Any:
        if value is None:
            raise CodecError(f"internal error: attempted to pass NULL {cls._name}")  # pragma: no mutate
        return cls._base.from_param(value)


class _NonNullU8P(_NonNullPointer):
    _base = _U8P
    _name = "uint8_t pointer"


class _NonNullU32P(_NonNullPointer):
    _base = _U32P
    _name = "uint32_t pointer"


class _NonNullFcallP(_NonNullPointer):
    _base = ctypes.POINTER(_Py9pFcall)
    _name = "Py9pFcall pointer"


class _NonNullDirP(_NonNullPointer):
    _base = ctypes.POINTER(_Py9pDir)
    _name = "Py9pDir pointer"


def _find_so() -> str:
    override = os.environ.get("PY9P_SO")
    if override:
        if not os.path.exists(override):
            raise NativeUnavailable(f"PY9P_SO={override} does not exist")  # pragma: no mutate
        return override

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(pkg_dir)
    for candidate in (
        os.path.join(pkg_dir, "libpy9p.so"),
        os.path.join(repo_root, "vendor", "libpy9p.so"),
    ):
        if os.path.exists(candidate):
            return candidate
    raise NativeUnavailable("libpy9p.so not found; install a wheel or run vendor/build.sh in a source checkout")  # pragma: no mutate


def _load() -> ctypes.CDLL:
    lib = ctypes.CDLL(_find_so())

    lib.py9p_lasterror.restype = ctypes.c_char_p
    lib.py9p_lasterror.argtypes = []
    lib.py9p_clear_error.restype = None
    lib.py9p_clear_error.argtypes = []

    lib.py9p_size_fcall.restype = ctypes.c_int
    lib.py9p_size_fcall.argtypes = [_NonNullFcallP, _NonNullU32P]
    lib.py9p_encode_fcall.restype = ctypes.c_int
    lib.py9p_encode_fcall.argtypes = [
        _NonNullFcallP,
        _NonNullU8P,
        ctypes.c_uint32,
        _NonNullU32P,
    ]
    lib.py9p_decode_fcall.restype = ctypes.c_int
    lib.py9p_decode_fcall.argtypes = [
        _NonNullU8P,
        ctypes.c_uint32,
        _NonNullFcallP,
        _NonNullU8P,
        ctypes.c_uint32,
    ]

    lib.py9p_size_dir.restype = ctypes.c_int
    lib.py9p_size_dir.argtypes = [_NonNullDirP, _NonNullU32P]
    lib.py9p_encode_dir.restype = ctypes.c_int
    lib.py9p_encode_dir.argtypes = [
        _NonNullDirP,
        _NonNullU8P,
        ctypes.c_uint32,
        _NonNullU32P,
    ]
    lib.py9p_decode_dir.restype = ctypes.c_int
    lib.py9p_decode_dir.argtypes = [
        _NonNullU8P,
        ctypes.c_uint32,
        _NonNullDirP,
        _NonNullU8P,
        ctypes.c_uint32,
        _NonNullU32P,
    ]
    lib.py9p_statcheck.restype = ctypes.c_int
    lib.py9p_statcheck.argtypes = [_NonNullU8P, ctypes.c_uint32]

    return lib


_lib: ctypes.CDLL | None = None


# Field and native-call context names are diagnostic text. Keep them on
# pragma-suppressed constants so validation bounds stay mutation-tested at
# their call sites without requiring exact error-string assertions.
_FIELD_AFID = "afid"  # pragma: no mutate
_FIELD_ANAME = "aname"  # pragma: no mutate
_FIELD_COUNT = "count"  # pragma: no mutate
_FIELD_DATA = "data"  # pragma: no mutate
_FIELD_DATA_LENGTH = "data length"  # pragma: no mutate
_FIELD_DIR_ATIME = "dir.atime"  # pragma: no mutate
_FIELD_DIR_DEV = "dir.dev"  # pragma: no mutate
_FIELD_DIR_GID = "dir.gid"  # pragma: no mutate
_FIELD_DIR_LENGTH = "dir.length"  # pragma: no mutate
_FIELD_DIR_MODE = "dir.mode"  # pragma: no mutate
_FIELD_DIR_MTIME = "dir.mtime"  # pragma: no mutate
_FIELD_DIR_MUID = "dir.muid"  # pragma: no mutate
_FIELD_DIR_NAME = "dir.name"  # pragma: no mutate
_FIELD_DIR_TYPE = "dir.type"  # pragma: no mutate
_FIELD_DIR_UID = "dir.uid"  # pragma: no mutate
_FIELD_ENAME = "ename"  # pragma: no mutate
_FIELD_ENCODED_DIR = "encoded dir"  # pragma: no mutate
_FIELD_ENCODED_MESSAGE = "encoded message"  # pragma: no mutate
_FIELD_FID = "fid"  # pragma: no mutate
_FIELD_IOUNIT = "iounit"  # pragma: no mutate
_FIELD_MODE = "mode"  # pragma: no mutate
_FIELD_MSIZE = "msize"  # pragma: no mutate
_FIELD_NAME = "name"  # pragma: no mutate
_FIELD_NEWFID = "newfid"  # pragma: no mutate
_FIELD_OLDTAG = "oldtag"  # pragma: no mutate
_FIELD_OFFSET = "offset"  # pragma: no mutate
_FIELD_PERM = "perm"  # pragma: no mutate
_FIELD_QID_PATH = "qid.path"  # pragma: no mutate
_FIELD_QID_TYPE = "qid.type"  # pragma: no mutate
_FIELD_QID_VERS = "qid.vers"  # pragma: no mutate
_FIELD_STAT = "stat"  # pragma: no mutate
_FIELD_TAG = "tag"  # pragma: no mutate
_FIELD_UNAME = "uname"  # pragma: no mutate
_FIELD_VERSION = "version"  # pragma: no mutate
_FIELD_WNAME = "wname"  # pragma: no mutate
_CTX_DECODE_DIR = "py9p_decode_dir"  # pragma: no mutate
_CTX_DECODE_FCALL = "py9p_decode_fcall"  # pragma: no mutate
_CTX_ENCODE_DIR = "py9p_encode_dir"  # pragma: no mutate
_CTX_ENCODE_FCALL = "py9p_encode_fcall"  # pragma: no mutate
_CTX_SIZE_DIR = "py9p_size_dir"  # pragma: no mutate
_CTX_SIZE_FCALL = "py9p_size_fcall"  # pragma: no mutate
_CTX_STATCHECK = "py9p_statcheck"  # pragma: no mutate
_TEXT_ENCODING = "utf-8"  # pragma: no mutate
_DECODE_REPLACEMENT = "replace"  # pragma: no mutate
_UNKNOWN_NATIVE_ERROR = "unknown native error"  # pragma: no mutate
_STAT_DECODE_SCRATCH_PADDING = 4  # pragma: no mutate


@dataclass(frozen=True, slots=True)
class _IntField:
    name: str
    min_value: int
    max_value: int


@dataclass(frozen=True, slots=True)
class _StrField:
    name: str


_INT_AFID = _IntField(
    _FIELD_AFID,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_COUNT = _IntField(
    _FIELD_COUNT,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_DATA_LENGTH = _IntField(
    _FIELD_DATA_LENGTH,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_DIR_ATIME = _IntField(
    _FIELD_DIR_ATIME,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_DIR_DEV = _IntField(
    _FIELD_DIR_DEV,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_DIR_LENGTH = _IntField(
    _FIELD_DIR_LENGTH,  # pragma: no mutate
    0,
    0x7FFFFFFFFFFFFFFF,
)
_INT_DIR_MODE = _IntField(
    _FIELD_DIR_MODE,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_DIR_MTIME = _IntField(
    _FIELD_DIR_MTIME,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_DIR_TYPE = _IntField(
    _FIELD_DIR_TYPE,  # pragma: no mutate
    0,
    0xFFFF,
)
_INT_FID = _IntField(
    _FIELD_FID,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_IOUNIT = _IntField(
    _FIELD_IOUNIT,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_MODE = _IntField(
    _FIELD_MODE,  # pragma: no mutate
    0,
    0xFF,
)
_INT_MSIZE = _IntField(
    _FIELD_MSIZE,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_NEWFID = _IntField(
    _FIELD_NEWFID,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_OLDTAG = _IntField(
    _FIELD_OLDTAG,  # pragma: no mutate
    0,
    0xFFFF,
)
_INT_OFFSET = _IntField(
    _FIELD_OFFSET,  # pragma: no mutate
    0,
    0x7FFFFFFFFFFFFFFF,
)
_INT_PERM = _IntField(
    _FIELD_PERM,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_QID_PATH = _IntField(
    _FIELD_QID_PATH,  # pragma: no mutate
    0,
    0xFFFFFFFFFFFFFFFF,
)
_INT_QID_TYPE = _IntField(
    _FIELD_QID_TYPE,  # pragma: no mutate
    0,
    0xFF,
)
_INT_QID_VERS = _IntField(
    _FIELD_QID_VERS,  # pragma: no mutate
    0,
    0xFFFFFFFF,
)
_INT_TAG = _IntField(
    _FIELD_TAG,  # pragma: no mutate
    0,
    0xFFFF,
)

_STR_ANAME = _StrField(
    _FIELD_ANAME,  # pragma: no mutate
)
_STR_DATA = _StrField(
    _FIELD_DATA,  # pragma: no mutate
)
_STR_DIR_GID = _StrField(
    _FIELD_DIR_GID,  # pragma: no mutate
)
_STR_DIR_MUID = _StrField(
    _FIELD_DIR_MUID,  # pragma: no mutate
)
_STR_DIR_NAME = _StrField(
    _FIELD_DIR_NAME,  # pragma: no mutate
)
_STR_DIR_UID = _StrField(
    _FIELD_DIR_UID,  # pragma: no mutate
)
_STR_ENAME = _StrField(
    _FIELD_ENAME,  # pragma: no mutate
)
_STR_NAME = _StrField(
    _FIELD_NAME,  # pragma: no mutate
)
_STR_STAT = _StrField(
    _FIELD_STAT,  # pragma: no mutate
)
_STR_UNAME = _StrField(
    _FIELD_UNAME,  # pragma: no mutate
)
_STR_VERSION = _StrField(
    _FIELD_VERSION,  # pragma: no mutate
)
_STR_WNAME = _StrField(
    _FIELD_WNAME,  # pragma: no mutate
)


def _check_field_int(value: int, field: _IntField) -> int:
    name = field.name  # pragma: no mutate
    return _check_int(value, name, field.min_value, field.max_value)


def _check_length(size: int, name: str, max_value: int) -> int:
    length_name = _length_field(name)  # pragma: no mutate
    return _check_int(size, length_name, 0, max_value)


def _require_field_bytes(value: object, field: _StrField) -> bytes:
    name = field.name  # pragma: no mutate
    return _require_bytes(value, name)


def _str_field(value: str | None, field: _StrField, *, required: bool) -> bytes | None:
    name = field.name  # pragma: no mutate
    return _str_bytes(value, name, required=required)  # pragma: no mutate


def _length_field(name: str) -> str:
    return f"{name} length"  # pragma: no mutate


def _get_lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = _load()
    return _lib


def _check_rc(lib: ctypes.CDLL, rc: int, context: str) -> None:
    if rc == 0:
        return
    err = lib.py9p_lasterror()
    msg = err.decode(_TEXT_ENCODING, _DECODE_REPLACEMENT) if err else _UNKNOWN_NATIVE_ERROR
    raise CodecError(f"{context}: {msg}")  # pragma: no mutate


def _require_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")  # pragma: no mutate
    return value


def _check_int(value: int, name: str, min_value: int, max_value: int) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")  # pragma: no mutate
    if value < min_value or value > max_value:
        raise ValueError(f"{name} must be in range {min_value}..{max_value}")  # pragma: no mutate
    return value


def _str_bytes(value: str | None, name: str, required: bool) -> bytes | None:
    if value is None:
        if required:
            raise TypeError(f"{name} is required")  # pragma: no mutate
        return None
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")  # pragma: no mutate
    if "\x00" in value:
        raise ValueError(f"{name} cannot contain NUL; plan9port Fcall strings are C strings")  # pragma: no mutate
    data = value.encode(_TEXT_ENCODING)
    if len(data) > 0xFFFF:
        raise ValueError(f"{name} is longer than the 9P 16-bit string limit")  # pragma: no mutate
    return data


def _decode_str(value: bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(_TEXT_ENCODING)


def _qid_to_raw(qid: Qid) -> _Py9pQid:
    if not isinstance(qid, Qid):
        raise TypeError(f"qid must be Qid, got {type(qid).__name__}")  # pragma: no mutate
    return _Py9pQid(
        _check_field_int(qid.type, _INT_QID_TYPE),
        _check_field_int(qid.vers, _INT_QID_VERS),
        _check_field_int(qid.path, _INT_QID_PATH),
    )


def _raw_to_qid(qid: _Py9pQid) -> Qid:
    return Qid(type=qid.type, vers=qid.vers, path=qid.path)


def _raw_stat_bytes(message: Rstat | Twstat) -> bytes:
    stat = message.stat
    if isinstance(stat, Dir):
        return encode_dir(stat)
    data = _require_field_bytes(stat, _STR_STAT)
    if len(data) > 0xFFFF:
        raise ValueError("stat is longer than the 9P nstat field")  # pragma: no mutate
    return data


def _bytes_buffer(data: bytes, keepalive: list[Any]) -> ctypes.c_void_p:
    buf = ctypes.create_string_buffer(data)
    keepalive.append(buf)
    return ctypes.cast(buf, ctypes.c_void_p)


def _message_to_raw(message: Message) -> tuple[_Py9pFcall, list[Any]]:
    keepalive: list[Any] = []
    raw = _Py9pFcall()
    raw.type = int(message.message_type)
    raw.tag = _check_field_int(message.tag, _INT_TAG)

    if isinstance(message, (Tversion, Rversion)):
        raw.msize = _check_field_int(message.msize, _INT_MSIZE)
        raw.version = _str_field(message.version, _STR_VERSION, required=True)
    elif isinstance(message, Tauth):
        raw.afid = _check_field_int(message.afid, _INT_AFID)
        raw.uname = _str_field(message.uname, _STR_UNAME, required=True)
        raw.aname = _str_field(message.aname, _STR_ANAME, required=True)
    elif isinstance(message, Rauth):
        raw.aqid = _qid_to_raw(message.aqid)
    elif isinstance(message, Tattach):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        raw.afid = _check_field_int(message.afid, _INT_AFID)
        raw.uname = _str_field(message.uname, _STR_UNAME, required=True)
        raw.aname = _str_field(message.aname, _STR_ANAME, required=True)
    elif isinstance(message, Rattach):
        raw.qid = _qid_to_raw(message.qid)
    elif isinstance(message, Rerror):
        raw.ename = _str_field(message.ename, _STR_ENAME, required=True)
    elif isinstance(message, Tflush):
        raw.oldtag = _check_field_int(message.oldtag, _INT_OLDTAG)
    elif isinstance(message, Rflush):
        pass
    elif isinstance(message, Twalk):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        raw.newfid = _check_field_int(message.newfid, _INT_NEWFID)
        raw.nwname = len(message.wname)
        for i, name in enumerate(message.wname):
            raw.wname[i] = _str_field(name, _STR_WNAME, required=True)
    elif isinstance(message, Rwalk):
        raw.nwqid = len(message.wqid)
        for i, qid in enumerate(message.wqid):
            raw.wqid[i] = _qid_to_raw(qid)
    elif isinstance(message, Topen):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        raw.mode = _check_field_int(int(message.mode), _INT_MODE)
    elif isinstance(message, (Ropen, Rcreate)):
        raw.qid = _qid_to_raw(message.qid)
        raw.iounit = _check_field_int(message.iounit, _INT_IOUNIT)
    elif isinstance(message, Tcreate):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        raw.name = _str_field(message.name, _STR_NAME, required=True)
        raw.perm = _check_field_int(message.perm, _INT_PERM)
        raw.mode = _check_field_int(int(message.mode), _INT_MODE)
    elif isinstance(message, Tread):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        raw.offset = _check_field_int(message.offset, _INT_OFFSET)
        raw.count = _check_field_int(message.count, _INT_COUNT)
    elif isinstance(message, Rread):
        data = _require_field_bytes(message.data, _STR_DATA)
        raw.count = _check_field_int(len(data), _INT_DATA_LENGTH)
        raw.data = _bytes_buffer(data, keepalive)
    elif isinstance(message, Twrite):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        raw.offset = _check_field_int(message.offset, _INT_OFFSET)
        data = _require_field_bytes(message.data, _STR_DATA)
        raw.count = _check_field_int(len(data), _INT_DATA_LENGTH)
        raw.data = _bytes_buffer(data, keepalive)
    elif isinstance(message, Rwrite):
        raw.count = _check_field_int(message.count, _INT_COUNT)
    elif isinstance(message, (Tclunk, Tremove, Tstat)):
        raw.fid = _check_field_int(message.fid, _INT_FID)
    elif isinstance(message, (Rclunk, Rremove, Rwstat)):
        pass
    elif isinstance(message, Rstat):
        stat = _raw_stat_bytes(message)
        raw.nstat = len(stat)
        raw.stat = _bytes_buffer(stat, keepalive)
    elif isinstance(message, Twstat):
        raw.fid = _check_field_int(message.fid, _INT_FID)
        stat = _raw_stat_bytes(message)
        raw.nstat = len(stat)
        raw.stat = _bytes_buffer(stat, keepalive)
    else:
        raise TypeError(f"unsupported message type {type(message).__name__}")  # pragma: no mutate

    return raw, keepalive


def message_size(message: Message) -> int:
    lib = _get_lib()
    raw, _keepalive = _message_to_raw(message)
    out = ctypes.c_uint32()
    rc = lib.py9p_size_fcall(ctypes.byref(raw), ctypes.byref(out))
    _check_rc(lib, rc, _CTX_SIZE_FCALL)  # pragma: no mutate
    return out.value


def encode_message(message: Message) -> bytes:
    lib = _get_lib()
    raw, _keepalive = _message_to_raw(message)
    size = message_size(message)
    out = ctypes.create_string_buffer(size)
    out_len = ctypes.c_uint32()
    rc = lib.py9p_encode_fcall(
        ctypes.byref(raw),
        ctypes.cast(out, _U8P),
        size,
        ctypes.byref(out_len),
    )
    _check_rc(lib, rc, _CTX_ENCODE_FCALL)  # pragma: no mutate
    return _buffer_bytes(out, out_len.value, _FIELD_ENCODED_MESSAGE)  # pragma: no mutate


def _buffer_bytes(buf: Any, size: int, name: str) -> bytes:
    cap = ctypes.sizeof(buf)
    size = _check_length(size, name, cap)
    return bytes(buf.raw[:size])


def _bytes_from_ptr(ptr: int | None, size: int, name: str, owner: Any) -> bytes:
    size = _check_length(size, name, ctypes.sizeof(owner))  # pragma: no mutate
    if size == 0:
        return b""
    if not ptr:
        raise CodecError(f"decoded {name} had a NULL pointer")  # pragma: no mutate
    addr = int(ptr)
    base = ctypes.addressof(owner)
    end = base + ctypes.sizeof(owner)
    if addr < base or addr + size > end:
        raise CodecError(f"decoded {name} pointer was outside the decode scratch buffer")  # pragma: no mutate
    offset = addr - base
    return bytes(owner.raw[offset : offset + size])


def _bytes_from_field_ptr(ptr: int | None, size: int, field: _StrField, owner: Any) -> bytes:
    name = field.name  # pragma: no mutate
    return _bytes_from_ptr(ptr, size, name, owner)  # pragma: no mutate


def _decode_stat_field(data: bytes) -> Dir | bytes:
    try:
        return decode_dir(data)
    except CodecError:
        return data


def _message_from_raw(raw: _Py9pFcall, scratch: Any) -> Message:
    try:
        msg_type = MessageType(raw.type)
    except ValueError as exc:
        raise CodecError(f"unsupported 9P message type {raw.type}") from exc  # pragma: no mutate

    tag = raw.tag
    if msg_type is MessageType.TVERSION:
        return Tversion(msize=raw.msize, version=_decode_str(raw.version), tag=tag)
    if msg_type is MessageType.RVERSION:
        return Rversion(msize=raw.msize, version=_decode_str(raw.version), tag=tag)
    if msg_type is MessageType.TAUTH:
        return Tauth(
            afid=raw.afid,
            uname=_decode_str(raw.uname),
            aname=_decode_str(raw.aname),
            tag=tag,
        )
    if msg_type is MessageType.RAUTH:
        return Rauth(aqid=_raw_to_qid(raw.aqid), tag=tag)
    if msg_type is MessageType.TATTACH:
        return Tattach(
            fid=raw.fid,
            afid=raw.afid,
            uname=_decode_str(raw.uname),
            aname=_decode_str(raw.aname),
            tag=tag,
        )
    if msg_type is MessageType.RATTACH:
        return Rattach(qid=_raw_to_qid(raw.qid), tag=tag)
    if msg_type is MessageType.RERROR:
        return Rerror(ename=_decode_str(raw.ename), tag=tag)
    if msg_type is MessageType.TFLUSH:
        return Tflush(oldtag=raw.oldtag, tag=tag)
    if msg_type is MessageType.RFLUSH:
        return Rflush(tag=tag)
    if msg_type is MessageType.TWALK:
        return Twalk(
            fid=raw.fid,
            newfid=raw.newfid,
            wname=tuple(_decode_str(raw.wname[i]) for i in range(raw.nwname)),
            tag=tag,
        )
    if msg_type is MessageType.RWALK:
        return Rwalk(wqid=tuple(_raw_to_qid(raw.wqid[i]) for i in range(raw.nwqid)), tag=tag)
    if msg_type is MessageType.TOPEN:
        return Topen(fid=raw.fid, mode=raw.mode, tag=tag)
    if msg_type is MessageType.ROPEN:
        return Ropen(qid=_raw_to_qid(raw.qid), iounit=raw.iounit, tag=tag)
    if msg_type is MessageType.TCREATE:
        return Tcreate(
            fid=raw.fid,
            name=_decode_str(raw.name),
            perm=raw.perm,
            mode=raw.mode,
            tag=tag,
        )
    if msg_type is MessageType.RCREATE:
        return Rcreate(qid=_raw_to_qid(raw.qid), iounit=raw.iounit, tag=tag)
    if msg_type is MessageType.TREAD:
        return Tread(fid=raw.fid, offset=raw.offset, count=raw.count, tag=tag)
    if msg_type is MessageType.RREAD:
        return Rread(data=_bytes_from_field_ptr(raw.data, raw.count, _STR_DATA, scratch), tag=tag)
    if msg_type is MessageType.TWRITE:
        return Twrite(
            fid=raw.fid,
            offset=raw.offset,
            data=_bytes_from_field_ptr(raw.data, raw.count, _STR_DATA, scratch),
            tag=tag,
        )
    if msg_type is MessageType.RWRITE:
        return Rwrite(count=raw.count, tag=tag)
    if msg_type is MessageType.TCLUNK:
        return Tclunk(fid=raw.fid, tag=tag)
    if msg_type is MessageType.RCLUNK:
        return Rclunk(tag=tag)
    if msg_type is MessageType.TREMOVE:
        return Tremove(fid=raw.fid, tag=tag)
    if msg_type is MessageType.RREMOVE:
        return Rremove(tag=tag)
    if msg_type is MessageType.TSTAT:
        return Tstat(fid=raw.fid, tag=tag)
    if msg_type is MessageType.RSTAT:
        data = _bytes_from_field_ptr(raw.stat, raw.nstat, _STR_STAT, scratch)
        return Rstat(stat=_decode_stat_field(data), tag=tag)
    if msg_type is MessageType.TWSTAT:
        data = _bytes_from_field_ptr(raw.stat, raw.nstat, _STR_STAT, scratch)
        return Twstat(fid=raw.fid, stat=_decode_stat_field(data), tag=tag)
    if msg_type is MessageType.RWSTAT:
        return Rwstat(tag=tag)
    raise CodecError(f"unsupported 9P message type {raw.type}")  # pragma: no mutate


def decode_message(data: bytes) -> Message:
    data = _require_field_bytes(data, _STR_DATA)
    lib = _get_lib()
    inbuf = ctypes.create_string_buffer(data)
    scratch = ctypes.create_string_buffer(len(data))
    raw = _Py9pFcall()
    rc = lib.py9p_decode_fcall(
        ctypes.cast(inbuf, _U8P),
        len(data),
        ctypes.byref(raw),
        ctypes.cast(scratch, _U8P),
        len(data),
    )
    _check_rc(lib, rc, _CTX_DECODE_FCALL)  # pragma: no mutate
    return _message_from_raw(raw, scratch)


def _dir_to_raw(entry: Dir) -> tuple[_Py9pDir, list[Any]]:
    if not isinstance(entry, Dir):
        raise TypeError(f"entry must be Dir, got {type(entry).__name__}")  # pragma: no mutate
    keepalive: list[Any] = []
    raw = _Py9pDir()
    raw.type = _check_field_int(entry.type, _INT_DIR_TYPE)
    raw.dev = _check_field_int(entry.dev, _INT_DIR_DEV)
    raw.qid = _qid_to_raw(entry.qid)
    raw.mode = _check_field_int(entry.mode, _INT_DIR_MODE)
    raw.atime = _check_field_int(entry.atime, _INT_DIR_ATIME)
    raw.mtime = _check_field_int(entry.mtime, _INT_DIR_MTIME)
    raw.length = _check_field_int(entry.length, _INT_DIR_LENGTH)
    raw.name = _str_field(entry.name, _STR_DIR_NAME, required=True)
    raw.uid = _str_field(entry.uid, _STR_DIR_UID, required=True)
    raw.gid = _str_field(entry.gid, _STR_DIR_GID, required=True)
    raw.muid = _str_field(entry.muid, _STR_DIR_MUID, required=True)
    keepalive.extend([raw.name, raw.uid, raw.gid, raw.muid])
    return raw, keepalive


def dir_size(entry: Dir) -> int:
    lib = _get_lib()
    raw, _keepalive = _dir_to_raw(entry)
    out = ctypes.c_uint32()
    rc = lib.py9p_size_dir(ctypes.byref(raw), ctypes.byref(out))
    _check_rc(lib, rc, _CTX_SIZE_DIR)  # pragma: no mutate
    return out.value


def encode_dir(entry: Dir) -> bytes:
    lib = _get_lib()
    raw, _keepalive = _dir_to_raw(entry)
    size = dir_size(entry)
    out = ctypes.create_string_buffer(size)
    out_len = ctypes.c_uint32()
    rc = lib.py9p_encode_dir(
        ctypes.byref(raw),
        ctypes.cast(out, _U8P),
        size,
        ctypes.byref(out_len),
    )
    _check_rc(lib, rc, _CTX_ENCODE_DIR)  # pragma: no mutate
    return _buffer_bytes(out, out_len.value, _FIELD_ENCODED_DIR)  # pragma: no mutate


def decode_dir(data: bytes) -> Dir:
    data = _require_field_bytes(data, _STR_DATA)
    lib = _get_lib()
    inbuf = ctypes.create_string_buffer(data)
    scratch = ctypes.create_string_buffer(len(data) + _STAT_DECODE_SCRATCH_PADDING)
    raw = _Py9pDir()
    out_len = ctypes.c_uint32()
    rc = lib.py9p_decode_dir(
        ctypes.cast(inbuf, _U8P),
        len(data),
        ctypes.byref(raw),
        ctypes.cast(scratch, _U8P),
        len(scratch),
        ctypes.byref(out_len),
    )
    _check_rc(lib, rc, _CTX_DECODE_DIR)  # pragma: no mutate
    return Dir(
        type=raw.type,
        dev=raw.dev,
        qid=_raw_to_qid(raw.qid),
        mode=raw.mode,
        atime=raw.atime,
        mtime=raw.mtime,
        length=raw.length,
        name=_decode_str(raw.name),
        uid=_decode_str(raw.uid),
        gid=_decode_str(raw.gid),
        muid=_decode_str(raw.muid),
    )


def statcheck(data: bytes) -> None:
    data = _require_field_bytes(data, _STR_DATA)
    lib = _get_lib()
    inbuf = ctypes.create_string_buffer(data)
    rc = lib.py9p_statcheck(ctypes.cast(inbuf, _U8P), len(data))
    _check_rc(lib, rc, _CTX_STATCHECK)


def with_tag(message: Message, tag: int) -> Message:
    return replace(message, tag=_check_field_int(tag, _INT_TAG))
