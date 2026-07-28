from __future__ import annotations

import os

import pytest

from py9p import CodecError, Dir, Qid, Rread, Tread, Twalk, decode_message, native


def test_find_so_override_must_exist(monkeypatch, tmp_path):
    missing = tmp_path / "missing.so"
    monkeypatch.setenv("PY9P_SO", str(missing))
    with pytest.raises(native.NativeUnavailable):
        native._find_so()


@pytest.mark.native
def test_non_bytes_payload_rejected_before_c(native_so):
    with pytest.raises(TypeError):
        Rread(data="not bytes").to_bytes()  # type: ignore[arg-type]


@pytest.mark.native
def test_nul_in_string_rejected_before_c(native_so):
    with pytest.raises(ValueError):
        Twalk(fid=0, newfid=1, wname=("bad\x00name",)).to_bytes()


def test_too_many_walk_elements_rejected():
    with pytest.raises(ValueError):
        Twalk(fid=0, newfid=1, wname=tuple(str(i) for i in range(17)))


@pytest.mark.native
def test_out_of_range_integer_rejected_before_c(native_so):
    with pytest.raises(ValueError):
        Tread(fid=0, offset=-1, count=1).to_bytes()


@pytest.mark.native
def test_bad_stat_rejected(native_so):
    with pytest.raises(CodecError):
        Dir.from_bytes(b"not a stat")


@pytest.mark.native
def test_decode_unknown_type_rejected(native_so):
    # size=7, type=255, tag=0
    with pytest.raises(CodecError):
        decode_message(b"\x07\x00\x00\x00\xff\x00\x00")


@pytest.mark.native
def test_find_so_uses_vendor_path(native_so, monkeypatch):
    monkeypatch.delenv("PY9P_SO", raising=False)
    assert os.path.samefile(native._find_so(), native_so)


def test_qid_type_validation():
    with pytest.raises(ValueError):
        native.encode_dir(Dir(qid=Qid(type=256)))
