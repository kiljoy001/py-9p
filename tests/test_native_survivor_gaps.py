from __future__ import annotations

import ctypes

import pytest

from py9p import CodecError, Dir, Qid, Rread, Tversion, Twalk, native


def test_require_bytes_error_names_argument_and_type():
    with pytest.raises(TypeError) as exc:
        native._require_bytes("abc", "payload")
    assert str(exc.value) == "payload must be bytes, got str"


def test_check_int_error_names_argument_type_and_range():
    with pytest.raises(TypeError) as exc:
        native._check_int("1", "fid", 0, 10)
    assert str(exc.value) == "fid must be int, got str"

    with pytest.raises(ValueError) as exc:
        native._check_int(11, "fid", 0, 10)
    assert str(exc.value) == "fid must be in range 0..10"


def test_required_string_rejects_none_with_context():
    with pytest.raises(TypeError) as exc:
        native._str_bytes(None, "version", required=True)
    assert str(exc.value) == "version is required"


def test_decode_str_handles_none_and_utf8_bytes():
    assert native._decode_str(None) == ""
    assert native._decode_str(b"glenda") == "glenda"


def test_qid_to_raw_rejects_wrong_type_with_context():
    with pytest.raises(TypeError) as exc:
        native._qid_to_raw(object())  # type: ignore[arg-type]
    assert str(exc.value) == "qid must be Qid, got object"


def test_nonnull_pointer_guard_message():
    with pytest.raises(native.CodecError) as exc:
        native._NonNullU8P.from_param(None)
    assert "NULL uint8_t pointer" in str(exc.value)


def test_with_tag_replaces_tag_and_validates_range():
    msg = native.with_tag(Tversion(msize=8192), 9)
    assert msg == Tversion(msize=8192, tag=9)
    with pytest.raises(ValueError, match="tag must be in range"):
        native.with_tag(Tversion(msize=8192), 0x10000)


def test_bytes_buffer_preserves_embedded_nul():
    keepalive: list[object] = []
    ptr = native._bytes_buffer(b"a\x00b", keepalive)
    assert ctypes.string_at(ptr, 3) == b"a\x00b"
    assert keepalive


def test_buffer_copy_helpers_validate_bounds():
    out = ctypes.create_string_buffer(b"abcdef")
    assert native._buffer_bytes(out, 3, "encoded message") == b"abc"
    with pytest.raises(ValueError, match="encoded message length"):
        native._buffer_bytes(out, ctypes.sizeof(out) + 1, "encoded message")

    scratch = ctypes.create_string_buffer(b"xxabcdef")
    ptr = ctypes.addressof(scratch) + 2
    assert native._bytes_from_ptr(ptr, 3, "data", scratch) == b"abc"
    with pytest.raises(native.CodecError, match="outside the decode scratch buffer"):
        native._bytes_from_ptr(ctypes.addressof(scratch) - 1, 3, "data", scratch)


@pytest.mark.native
def test_none_in_required_message_fields_is_rejected(native_so):
    for message in (
        Tversion(version=None),  # type: ignore[arg-type]
        Twalk(fid=1, newfid=2, wname=(None,)),  # type: ignore[list-item]
    ):
        with pytest.raises(TypeError):
            native.encode_message(message)


@pytest.mark.native
def test_non_bytes_data_message_has_exact_context(native_so):
    with pytest.raises(TypeError) as exc:
        native.encode_message(Rread(data=bytearray(b"abc")))  # type: ignore[arg-type]
    assert str(exc.value) == "data must be bytes, got bytearray"


@pytest.mark.native
def test_statcheck_accepts_valid_stat_and_rejects_bad_inputs(native_so):
    valid = Dir(qid=Qid(path=1), name="n", uid="u", gid="g", muid="m").to_bytes()
    assert native.statcheck(valid) is None

    with pytest.raises(TypeError) as exc:
        native.statcheck("not bytes")  # type: ignore[arg-type]
    assert str(exc.value) == "data must be bytes, got str"

    with pytest.raises(CodecError, match="py9p_statcheck"):
        native.statcheck(b"bad stat")


def test_get_lib_populates_cache(monkeypatch):
    marker = object()
    monkeypatch.setattr(native, "_lib", None)
    monkeypatch.setattr(native, "_load", lambda: marker)
    assert native._get_lib() is marker
    assert native._get_lib() is marker
