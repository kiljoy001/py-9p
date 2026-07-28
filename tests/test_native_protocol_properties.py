from __future__ import annotations

import ctypes
from dataclasses import replace
from typing import NamedTuple

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings
from hypothesis import strategies as st

from py9p import (
    CodecError,
    Dir,
    Message,
    MessageType,
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
    native,
)

U8_MAX = 0xFF
U16_MAX = 0xFFFF
U32_MAX = 0xFFFFFFFF
U64_MAX = 0xFFFFFFFFFFFFFFFF
I63_MAX = 0x7FFFFFFFFFFFFFFF


def boundary_int(min_value: int, max_value: int) -> st.SearchStrategy[int]:
    edges = [min_value, min_value + 1, max_value - 1, max_value]
    return st.one_of(st.sampled_from(edges), st.integers(min_value=min_value, max_value=max_value))


u8s = boundary_int(0, U8_MAX)
u16s = boundary_int(0, U16_MAX)
u32s = boundary_int(0, U32_MAX)
u64s = boundary_int(0, U64_MAX)
i63s = boundary_int(0, I63_MAX)
texts = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    max_size=16,
)
blobs = st.binary(max_size=96)

qids = st.builds(Qid, type=u8s, vers=u32s, path=u64s)
dirs = st.builds(
    Dir,
    type=u16s,
    dev=u32s,
    qid=qids,
    mode=u32s,
    atime=u32s,
    mtime=u32s,
    length=i63s,
    name=texts,
    uid=texts,
    gid=texts,
    muid=texts,
)

messages = st.one_of(
    st.builds(Tversion, msize=u32s, version=texts, tag=u16s),
    st.builds(Rversion, msize=u32s, version=texts, tag=u16s),
    st.builds(Tauth, afid=u32s, uname=texts, aname=texts, tag=u16s),
    st.builds(Rauth, aqid=qids, tag=u16s),
    st.builds(Tattach, fid=u32s, afid=u32s, uname=texts, aname=texts, tag=u16s),
    st.builds(Rattach, qid=qids, tag=u16s),
    st.builds(Rerror, ename=texts, tag=u16s),
    st.builds(Tflush, oldtag=u16s, tag=u16s),
    st.builds(Rflush, tag=u16s),
    st.builds(Twalk, fid=u32s, newfid=u32s, wname=st.lists(texts, max_size=16).map(tuple), tag=u16s),
    st.builds(Rwalk, wqid=st.lists(qids, max_size=16).map(tuple), tag=u16s),
    st.builds(Topen, fid=u32s, mode=u8s, tag=u16s),
    st.builds(Ropen, qid=qids, iounit=u32s, tag=u16s),
    st.builds(Tcreate, fid=u32s, name=texts, perm=u32s, mode=u8s, tag=u16s),
    st.builds(Rcreate, qid=qids, iounit=u32s, tag=u16s),
    st.builds(Tread, fid=u32s, offset=i63s, count=u32s, tag=u16s),
    st.builds(Rread, data=blobs, tag=u16s),
    st.builds(Twrite, fid=u32s, offset=i63s, data=blobs, tag=u16s),
    st.builds(Rwrite, count=u32s, tag=u16s),
    st.builds(Tclunk, fid=u32s, tag=u16s),
    st.builds(Rclunk, tag=u16s),
    st.builds(Tremove, fid=u32s, tag=u16s),
    st.builds(Rremove, tag=u16s),
    st.builds(Tstat, fid=u32s, tag=u16s),
    st.builds(Rstat, stat=dirs, tag=u16s),
    st.builds(Twstat, fid=u32s, stat=dirs, tag=u16s),
    st.builds(Rwstat, tag=u16s),
)


def _raw_qid_tuple(qid: native._Py9pQid) -> tuple[int, int, int]:
    return (qid.type, qid.vers, qid.path)


def _qid_tuple(qid: Qid) -> tuple[int, int, int]:
    return (qid.type, qid.vers, qid.path)


def _pointer_bytes(ptr: int | None, size: int) -> bytes:
    return b"" if size == 0 else ctypes.string_at(ptr, size)


def _stat_bytes(stat: Dir | bytes) -> bytes:
    return stat.to_bytes() if isinstance(stat, Dir) else stat


def assert_raw_message_matches(message: Message, raw: native._Py9pFcall) -> None:
    assert raw.type == int(message.message_type)
    assert raw.tag == message.tag

    if isinstance(message, (Tversion, Rversion)):
        assert raw.msize == message.msize
        assert raw.version == message.version.encode("utf-8")
    elif isinstance(message, Tauth):
        assert (raw.afid, raw.uname, raw.aname) == (
            message.afid,
            message.uname.encode("utf-8"),
            message.aname.encode("utf-8"),
        )
    elif isinstance(message, Rauth):
        assert _raw_qid_tuple(raw.aqid) == _qid_tuple(message.aqid)
    elif isinstance(message, Tattach):
        assert (raw.fid, raw.afid, raw.uname, raw.aname) == (
            message.fid,
            message.afid,
            message.uname.encode("utf-8"),
            message.aname.encode("utf-8"),
        )
    elif isinstance(message, Rattach):
        assert _raw_qid_tuple(raw.qid) == _qid_tuple(message.qid)
    elif isinstance(message, Rerror):
        assert raw.ename == message.ename.encode("utf-8")
    elif isinstance(message, Tflush):
        assert raw.oldtag == message.oldtag
    elif isinstance(message, Twalk):
        assert (raw.fid, raw.newfid, raw.nwname) == (
            message.fid,
            message.newfid,
            len(message.wname),
        )
        assert tuple(raw.wname[i] for i in range(raw.nwname)) == tuple(
            name.encode("utf-8") for name in message.wname
        )
    elif isinstance(message, Rwalk):
        assert raw.nwqid == len(message.wqid)
        assert tuple(_raw_qid_tuple(raw.wqid[i]) for i in range(raw.nwqid)) == tuple(
            _qid_tuple(qid) for qid in message.wqid
        )
    elif isinstance(message, Topen):
        assert (raw.fid, raw.mode) == (message.fid, int(message.mode))
    elif isinstance(message, (Ropen, Rcreate)):
        assert _raw_qid_tuple(raw.qid) == _qid_tuple(message.qid)
        assert raw.iounit == message.iounit
    elif isinstance(message, Tcreate):
        assert (raw.fid, raw.name, raw.perm, raw.mode) == (
            message.fid,
            message.name.encode("utf-8"),
            message.perm,
            int(message.mode),
        )
    elif isinstance(message, Tread):
        assert (raw.fid, raw.offset, raw.count) == (message.fid, message.offset, message.count)
    elif isinstance(message, Rread):
        assert raw.count == len(message.data)
        assert _pointer_bytes(raw.data, raw.count) == message.data
    elif isinstance(message, Twrite):
        assert (raw.fid, raw.offset, raw.count) == (
            message.fid,
            message.offset,
            len(message.data),
        )
        assert _pointer_bytes(raw.data, raw.count) == message.data
    elif isinstance(message, Rwrite):
        assert raw.count == message.count
    elif isinstance(message, (Tclunk, Tremove, Tstat)):
        assert raw.fid == message.fid
    elif isinstance(message, (Rflush, Rclunk, Rremove, Rwstat)):
        assert raw.type == int(message.message_type)
    elif isinstance(message, Rstat):
        expected = _stat_bytes(message.stat)
        assert raw.nstat == len(expected)
        assert _pointer_bytes(raw.stat, raw.nstat) == expected
    elif isinstance(message, Twstat):
        expected = _stat_bytes(message.stat)
        assert raw.fid == message.fid
        assert raw.nstat == len(expected)
        assert _pointer_bytes(raw.stat, raw.nstat) == expected
    else:
        raise TypeError(f"missing raw assertion for {type(message).__name__}")


@pytest.mark.native
@given(message=messages)
@settings(max_examples=160, deadline=None)
def test_message_to_raw_preserves_generated_fields(message: Message, native_so: str) -> None:
    raw, keepalive = native._message_to_raw(message)
    assert keepalive is not None
    assert_raw_message_matches(message, raw)


@pytest.mark.native
@given(entry=dirs)
@settings(max_examples=120, deadline=None)
def test_dir_to_raw_preserves_generated_fields(entry: Dir, native_so: str) -> None:
    raw, keepalive = native._dir_to_raw(entry)
    assert keepalive is not None
    assert (raw.type, raw.dev, raw.mode, raw.atime, raw.mtime, raw.length) == (
        entry.type,
        entry.dev,
        entry.mode,
        entry.atime,
        entry.mtime,
        entry.length,
    )
    assert _raw_qid_tuple(raw.qid) == _qid_tuple(entry.qid)
    assert (raw.name, raw.uid, raw.gid, raw.muid) == (
        entry.name.encode("utf-8"),
        entry.uid.encode("utf-8"),
        entry.gid.encode("utf-8"),
        entry.muid.encode("utf-8"),
    )


@given(message_type=st.sampled_from((MessageType.TVERSION, MessageType.RVERSION)), tag=u16s)
@settings(max_examples=40, deadline=None)
def test_message_from_raw_preserves_generated_version_tags(
    message_type: MessageType, tag: int
) -> None:
    raw = native._Py9pFcall()
    raw.type = int(message_type)
    raw.tag = tag
    raw.msize = 8192
    raw.version = b"9P2000"
    message = native._message_from_raw(raw, ctypes.create_string_buffer(0))
    assert message.tag == tag


@given(fid=u32s, afid=u32s, uname=texts.filter(bool), aname=texts.filter(bool), tag=u16s)
@settings(max_examples=80, deadline=None)
def test_message_from_raw_preserves_generated_attach_names(
    fid: int, afid: int, uname: str, aname: str, tag: int
) -> None:
    raw = native._Py9pFcall()
    raw.type = int(MessageType.TATTACH)
    raw.tag = tag
    raw.fid = fid
    raw.afid = afid
    raw.uname = uname.encode("utf-8")
    raw.aname = aname.encode("utf-8")
    assert native._message_from_raw(raw, ctypes.create_string_buffer(0)) == Tattach(
        fid=fid,
        afid=afid,
        uname=uname,
        aname=aname,
        tag=tag,
    )


safe_path_parts = st.lists(
    st.from_regex(r"[A-Za-z0-9_]{1,8}", fullmatch=True),
    min_size=1,
    max_size=3,
).map(lambda parts: "/" + "/".join(parts))


@given(root=safe_path_parts, prefer_package_lib=st.booleans())
@settings(max_examples=30, deadline=None)
def test_find_so_selects_generated_package_then_vendor_candidates(
    root: str, prefer_package_lib: bool
) -> None:
    package_dir = f"{root}/py9p"
    package_lib = f"{package_dir}/libpy9p.so"
    vendor_lib = f"{root}/vendor/libpy9p.so"
    existing = {package_lib} if prefer_package_lib else {vendor_lib}
    old_file = native.__file__
    old_exists = native.os.path.exists
    had_override = "PY9P_SO" in native.os.environ
    old_override = native.os.environ.get("PY9P_SO")
    native.__file__ = f"{package_dir}/native.py"
    native.os.environ.pop("PY9P_SO", None)
    native.os.path.exists = lambda path: path in existing  # type: ignore[method-assign]
    try:
        assert native._find_so() == (package_lib if prefer_package_lib else vendor_lib)
    finally:
        native.__file__ = old_file
        native.os.path.exists = old_exists  # type: ignore[method-assign]
        if had_override:
            assert old_override is not None
            native.os.environ["PY9P_SO"] = old_override
        else:
            native.os.environ.pop("PY9P_SO", None)


class NumericCase(NamedTuple):
    value: object
    field: str
    min_value: int
    max_value: int


VALID_DIR = Dir(qid=Qid(path=1), name="n", uid="u", gid="g", muid="m")
VALID_QID = Qid(type=1, vers=2, path=3)

MESSAGE_NUMERIC_CASES = (
    NumericCase(Tversion(msize=8192, tag=1), "tag", 0, U16_MAX),
    NumericCase(Tversion(msize=8192, tag=1), "msize", 0, U32_MAX),
    NumericCase(Rversion(msize=8192, tag=1), "msize", 0, U32_MAX),
    NumericCase(Tauth(afid=1, uname="u", aname="a", tag=1), "afid", 0, U32_MAX),
    NumericCase(Tattach(fid=1, afid=2, uname="u", aname="a", tag=1), "fid", 0, U32_MAX),
    NumericCase(Tattach(fid=1, afid=2, uname="u", aname="a", tag=1), "afid", 0, U32_MAX),
    NumericCase(Tflush(oldtag=1, tag=2), "oldtag", 0, U16_MAX),
    NumericCase(Twalk(fid=1, newfid=2, wname=("a",), tag=1), "fid", 0, U32_MAX),
    NumericCase(Twalk(fid=1, newfid=2, wname=("a",), tag=1), "newfid", 0, U32_MAX),
    NumericCase(Topen(fid=1, mode=0, tag=1), "fid", 0, U32_MAX),
    NumericCase(Topen(fid=1, mode=0, tag=1), "mode", 0, U8_MAX),
    NumericCase(Ropen(qid=VALID_QID, iounit=1, tag=1), "iounit", 0, U32_MAX),
    NumericCase(Tcreate(fid=1, name="n", perm=0, mode=0, tag=1), "fid", 0, U32_MAX),
    NumericCase(Tcreate(fid=1, name="n", perm=0, mode=0, tag=1), "perm", 0, U32_MAX),
    NumericCase(Tcreate(fid=1, name="n", perm=0, mode=0, tag=1), "mode", 0, U8_MAX),
    NumericCase(Tread(fid=1, offset=0, count=0, tag=1), "fid", 0, U32_MAX),
    NumericCase(Tread(fid=1, offset=0, count=0, tag=1), "offset", 0, I63_MAX),
    NumericCase(Tread(fid=1, offset=0, count=0, tag=1), "count", 0, U32_MAX),
    NumericCase(Twrite(fid=1, offset=0, data=b"x", tag=1), "fid", 0, U32_MAX),
    NumericCase(Twrite(fid=1, offset=0, data=b"x", tag=1), "offset", 0, I63_MAX),
    NumericCase(Rwrite(count=1, tag=1), "count", 0, U32_MAX),
    NumericCase(Tclunk(fid=1, tag=1), "fid", 0, U32_MAX),
    NumericCase(Tremove(fid=1, tag=1), "fid", 0, U32_MAX),
    NumericCase(Tstat(fid=1, tag=1), "fid", 0, U32_MAX),
    NumericCase(Twstat(fid=1, stat=VALID_DIR, tag=1), "fid", 0, U32_MAX),
)

DIR_NUMERIC_CASES = (
    NumericCase(VALID_DIR, "type", 0, U16_MAX),
    NumericCase(VALID_DIR, "dev", 0, U32_MAX),
    NumericCase(VALID_DIR, "mode", 0, U32_MAX),
    NumericCase(VALID_DIR, "atime", 0, U32_MAX),
    NumericCase(VALID_DIR, "mtime", 0, U32_MAX),
    NumericCase(VALID_DIR, "length", 0, I63_MAX),
)

QID_NUMERIC_CASES = (
    NumericCase(VALID_QID, "type", 0, U8_MAX),
    NumericCase(VALID_QID, "vers", 0, U32_MAX),
    NumericCase(VALID_QID, "path", 0, U64_MAX),
)


def _bad_bound(case: NumericCase, side: str) -> int:
    return case.min_value - 1 if side == "below" else case.max_value + 1


@pytest.mark.native
@given(case=st.sampled_from(MESSAGE_NUMERIC_CASES), side=st.sampled_from(("below", "above")))
@settings(max_examples=100, deadline=None)
def test_message_numeric_bounds_reject_generated_out_of_range_values(
    case: NumericCase, side: str, native_so: str
) -> None:
    message = replace(case.value, **{case.field: _bad_bound(case, side)})
    with pytest.raises(ValueError):
        native._message_to_raw(message)


@pytest.mark.native
@given(case=st.sampled_from(DIR_NUMERIC_CASES), side=st.sampled_from(("below", "above")))
@settings(max_examples=60, deadline=None)
def test_dir_numeric_bounds_reject_generated_out_of_range_values(
    case: NumericCase, side: str, native_so: str
) -> None:
    entry = replace(case.value, **{case.field: _bad_bound(case, side)})
    with pytest.raises(ValueError):
        native._dir_to_raw(entry)


@given(case=st.sampled_from(QID_NUMERIC_CASES), side=st.sampled_from(("below", "above")))
@settings(max_examples=30, deadline=None)
def test_qid_numeric_bounds_reject_generated_out_of_range_values(
    case: NumericCase, side: str
) -> None:
    qid = replace(case.value, **{case.field: _bad_bound(case, side)})
    with pytest.raises(ValueError):
        native._qid_to_raw(qid)


oversized_text = st.just("x" * (U16_MAX + 1))
nul_text = texts.map(lambda value: value + "\x00")
bad_required_text = st.one_of(st.none(), nul_text, oversized_text)

MESSAGE_TEXT_CASES = (
    (Tversion(msize=8192, version="9P2000", tag=1), "version"),
    (Rversion(msize=8192, version="9P2000", tag=1), "version"),
    (Tauth(afid=1, uname="u", aname="a", tag=1), "uname"),
    (Tauth(afid=1, uname="u", aname="a", tag=1), "aname"),
    (Tattach(fid=1, afid=2, uname="u", aname="a", tag=1), "uname"),
    (Tattach(fid=1, afid=2, uname="u", aname="a", tag=1), "aname"),
    (Rerror(ename="e", tag=1), "ename"),
    (Tcreate(fid=1, name="n", perm=0, mode=0, tag=1), "name"),
    (Twalk(fid=1, newfid=2, wname=("ok",), tag=1), "wname"),
)

DIR_TEXT_CASES = (
    (VALID_DIR, "name"),
    (VALID_DIR, "uid"),
    (VALID_DIR, "gid"),
    (VALID_DIR, "muid"),
)


@pytest.mark.native
@given(case=st.sampled_from(MESSAGE_TEXT_CASES), bad_text=bad_required_text)
@settings(max_examples=80, deadline=None)
def test_message_required_strings_reject_generated_invalid_text(
    case: tuple[Message, str], bad_text: str | None, native_so: str
) -> None:
    message, field = case
    if field == "wname":
        invalid = replace(message, wname=(bad_text,))  # type: ignore[arg-type]
    else:
        invalid = replace(message, **{field: bad_text})
    with pytest.raises((TypeError, ValueError)):
        native._message_to_raw(invalid)


@pytest.mark.native
@given(case=st.sampled_from(DIR_TEXT_CASES), bad_text=bad_required_text)
@settings(max_examples=60, deadline=None)
def test_dir_required_strings_reject_generated_invalid_text(
    case: tuple[Dir, str], bad_text: str | None, native_so: str
) -> None:
    entry, field = case
    with pytest.raises((TypeError, ValueError)):
        native._dir_to_raw(replace(entry, **{field: bad_text}))


@given(field=st.sampled_from((native._STR_VERSION, native._STR_NAME, native._STR_DIR_NAME)))
@settings(max_examples=3, deadline=None)
def test_required_strings_accept_generated_exact_16bit_limit(field: native._StrField) -> None:
    value = "x" * U16_MAX
    assert native._str_field(value, field, required=True) == b"x" * U16_MAX


@pytest.mark.native
@given(
    message_type=st.sampled_from((MessageType.RSTAT, MessageType.TWSTAT)),
    extra=st.integers(min_value=0, max_value=4),
)
@settings(max_examples=10, deadline=None)
def test_raw_stat_bytes_rejects_generated_oversized_stat(
    message_type: MessageType, extra: int, native_so: str
) -> None:
    stat = b"x" * (U16_MAX + 1 + extra)
    message = Rstat(stat=stat, tag=1) if message_type is MessageType.RSTAT else Twstat(fid=1, stat=stat, tag=1)
    with pytest.raises(ValueError):
        native._raw_stat_bytes(message)


@pytest.mark.native
@given(message_type=st.sampled_from((MessageType.RSTAT, MessageType.TWSTAT)))
@settings(max_examples=2, deadline=None)
def test_raw_stat_bytes_accepts_generated_max_sized_raw_stat(
    message_type: MessageType, native_so: str
) -> None:
    stat = b"x" * U16_MAX
    message = Rstat(stat=stat, tag=1) if message_type is MessageType.RSTAT else Twstat(fid=1, stat=stat, tag=1)
    assert native._raw_stat_bytes(message) == stat


@st.composite
def scratch_slices(draw: st.DrawFn) -> tuple[bytes, int, int]:
    data = draw(st.binary(min_size=1, max_size=64))
    start = draw(st.integers(min_value=0, max_value=len(data)))
    size = draw(st.integers(min_value=0, max_value=len(data) - start))
    return data, start, size


@given(case=scratch_slices())
@settings(max_examples=100, deadline=None)
def test_bytes_from_ptr_copies_generated_in_buffer_slices(case: tuple[bytes, int, int]) -> None:
    data, start, size = case
    scratch = ctypes.create_string_buffer(data, len(data))
    ptr = ctypes.addressof(scratch) + start
    assert native._bytes_from_ptr(ptr, size, "payload", scratch) == data[start : start + size]


@given(data=st.binary(min_size=1, max_size=64))
@settings(max_examples=50, deadline=None)
def test_bytes_from_ptr_rejects_generated_out_of_buffer_ranges(data: bytes) -> None:
    scratch = ctypes.create_string_buffer(data, len(data))
    base = ctypes.addressof(scratch)

    with pytest.raises(CodecError):
        native._bytes_from_ptr(base - 1, 1, "payload", scratch)

    with pytest.raises(CodecError):
        native._bytes_from_ptr(base + len(data), 1, "payload", scratch)

    with pytest.raises(ValueError):
        native._bytes_from_ptr(base, len(data) + 1, "payload", scratch)


@given(data=st.binary(max_size=64))
@settings(max_examples=60, deadline=None)
def test_bytes_buffer_keeps_generated_ctypes_buffer_alive(data: bytes) -> None:
    keepalive: list[object] = []
    ptr = native._bytes_buffer(data, keepalive)
    assert len(keepalive) == 1
    assert keepalive[0] is not None
    assert ctypes.string_at(ptr, len(data)) == data


class FakeLib:
    def __init__(self, payload: bytes | None) -> None:
        self.payload = payload
        self.calls = 0

    def py9p_lasterror(self) -> bytes | None:
        self.calls += 1
        return self.payload


@given(payload=texts.filter(bool).map(lambda value: value.encode("utf-8")))
@settings(max_examples=40, deadline=None)
def test_check_rc_surfaces_generated_native_error_payload(payload: bytes) -> None:
    lib = FakeLib(payload)
    with pytest.raises(CodecError) as exc:
        native._check_rc(lib, 1, "native call")
    assert lib.calls == 1
    assert payload.decode("utf-8") in str(exc.value)


@given(payload=st.sampled_from((b"\xff", b"\xc3(", b"\xe2\x28\xa1")))
@settings(max_examples=3, deadline=None)
def test_check_rc_replaces_generated_invalid_utf8_errors(payload: bytes) -> None:
    lib = FakeLib(payload)
    with pytest.raises(CodecError):
        native._check_rc(lib, 1, "native call")
    assert lib.calls == 1


FFI_SIGNATURES = {
    "py9p_lasterror": (ctypes.c_char_p, []),
    "py9p_clear_error": (None, []),
    "py9p_size_fcall": (ctypes.c_int, [native._NonNullFcallP, native._NonNullU32P]),
    "py9p_encode_fcall": (
        ctypes.c_int,
        [native._NonNullFcallP, native._NonNullU8P, ctypes.c_uint32, native._NonNullU32P],
    ),
    "py9p_decode_fcall": (
        ctypes.c_int,
        [
            native._NonNullU8P,
            ctypes.c_uint32,
            native._NonNullFcallP,
            native._NonNullU8P,
            ctypes.c_uint32,
        ],
    ),
    "py9p_size_dir": (ctypes.c_int, [native._NonNullDirP, native._NonNullU32P]),
    "py9p_encode_dir": (
        ctypes.c_int,
        [native._NonNullDirP, native._NonNullU8P, ctypes.c_uint32, native._NonNullU32P],
    ),
    "py9p_decode_dir": (
        ctypes.c_int,
        [
            native._NonNullU8P,
            ctypes.c_uint32,
            native._NonNullDirP,
            native._NonNullU8P,
            ctypes.c_uint32,
            native._NonNullU32P,
        ],
    ),
    "py9p_statcheck": (ctypes.c_int, [native._NonNullU8P, ctypes.c_uint32]),
}


class FakeSymbol:
    restype: object = object()
    argtypes: object = object()


class FakeCDLL:
    def __init__(self, path: str) -> None:
        self.path = path
        for name in FFI_SIGNATURES:
            setattr(self, name, FakeSymbol())


@given(path=texts.filter(bool))
@settings(max_examples=12, deadline=None)
def test_load_assigns_generated_fake_cdll_signatures(path: str) -> None:
    fake = FakeCDLL(path)
    old_cdll = native.ctypes.CDLL
    old_find_so = native._find_so
    native.ctypes.CDLL = lambda _: fake  # type: ignore[method-assign]
    native._find_so = lambda: path  # type: ignore[method-assign]
    try:
        loaded = native._load()
    finally:
        native.ctypes.CDLL = old_cdll  # type: ignore[method-assign]
        native._find_so = old_find_so  # type: ignore[method-assign]

    assert loaded is fake
    assert fake.path == path
    for name, (restype, argtypes) in FFI_SIGNATURES.items():
        symbol = getattr(fake, name)
        assert symbol.restype == restype
        assert symbol.argtypes == argtypes


class FailingNativeLib:
    def __init__(self, fail: str) -> None:
        self.fail = fail

    def py9p_lasterror(self) -> bytes:
        return b"native failure"

    def py9p_size_fcall(self, _raw: object, out: object) -> int:
        if self.fail == "py9p_size_fcall":
            return 1
        ctypes.cast(out, ctypes.POINTER(ctypes.c_uint32))[0] = 19
        return 0

    def py9p_encode_fcall(
        self, _raw: object, _out: object, _size: int, _out_len: object
    ) -> int:
        return 1 if self.fail == "py9p_encode_fcall" else 0

    def py9p_decode_fcall(
        self, _data: object, _size: int, _raw: object, _scratch: object, _scratch_size: int
    ) -> int:
        return 1 if self.fail == "py9p_decode_fcall" else 0

    def py9p_size_dir(self, _raw: object, out: object) -> int:
        if self.fail == "py9p_size_dir":
            return 1
        ctypes.cast(out, ctypes.POINTER(ctypes.c_uint32))[0] = 64
        return 0

    def py9p_encode_dir(self, _raw: object, _out: object, _size: int, _out_len: object) -> int:
        return 1 if self.fail == "py9p_encode_dir" else 0

    def py9p_decode_dir(
        self,
        _data: object,
        _size: int,
        _raw: object,
        _scratch: object,
        _scratch_size: int,
        _out_len: object,
    ) -> int:
        return 1 if self.fail == "py9p_decode_dir" else 0

    def py9p_statcheck(self, _data: object, _size: int) -> int:
        return 1 if self.fail == "py9p_statcheck" else 0


FAILING_OPS = (
    "py9p_size_fcall",
    "py9p_encode_fcall",
    "py9p_decode_fcall",
    "py9p_size_dir",
    "py9p_encode_dir",
    "py9p_decode_dir",
    "py9p_statcheck",
)


@pytest.mark.native
@given(failing_op=st.sampled_from(FAILING_OPS))
@settings(max_examples=len(FAILING_OPS), deadline=None)
def test_generated_native_failures_raise_codec_error(failing_op: str, native_so: str) -> None:
    message_wire = bytes.fromhex("1300000064ffff002000000600395032303030")
    dir_wire = VALID_DIR.to_bytes()
    old_get_lib = native._get_lib
    native._get_lib = lambda: FailingNativeLib(failing_op)  # type: ignore[method-assign]
    try:
        with pytest.raises(CodecError):
            if failing_op == "py9p_size_fcall":
                native.message_size(Tversion(msize=8192))
            elif failing_op == "py9p_encode_fcall":
                native.encode_message(Tversion(msize=8192))
            elif failing_op == "py9p_decode_fcall":
                native.decode_message(message_wire)
            elif failing_op == "py9p_size_dir":
                native.dir_size(VALID_DIR)
            elif failing_op == "py9p_encode_dir":
                native.encode_dir(VALID_DIR)
            elif failing_op == "py9p_decode_dir":
                native.decode_dir(dir_wire)
            elif failing_op == "py9p_statcheck":
                native.statcheck(dir_wire)
            else:
                raise TypeError(f"unknown failing operation {failing_op}")
    finally:
        native._get_lib = old_get_lib  # type: ignore[method-assign]
