from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings
from hypothesis import strategies as st

from py9p import (
    Dir,
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
    decode_message,
    encode_message,
)

small_u8 = st.integers(min_value=0, max_value=255)
small_u16 = st.integers(min_value=0, max_value=65535)
small_u32 = st.integers(min_value=0, max_value=2**32 - 1)
small_i64 = st.integers(min_value=0, max_value=2**31)
text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    max_size=24,
)
blob = st.binary(max_size=256)

qids = st.builds(Qid, type=small_u8, vers=small_u32, path=st.integers(0, 2**64 - 1))
dirs = st.builds(
    Dir,
    type=small_u16,
    dev=small_u32,
    qid=qids,
    mode=small_u32,
    atime=small_u32,
    mtime=small_u32,
    length=small_i64,
    name=text,
    uid=text,
    gid=text,
    muid=text,
)

messages = st.one_of(
    st.builds(Tversion, msize=small_u32, version=text, tag=st.just(65535)),
    st.builds(Rversion, msize=small_u32, version=text, tag=st.just(65535)),
    st.builds(Tauth, afid=small_u32, uname=text, aname=text, tag=small_u16),
    st.builds(Rauth, aqid=qids, tag=small_u16),
    st.builds(Tattach, fid=small_u32, afid=small_u32, uname=text, aname=text, tag=small_u16),
    st.builds(Rattach, qid=qids, tag=small_u16),
    st.builds(Rerror, ename=text, tag=small_u16),
    st.builds(Tflush, oldtag=small_u16, tag=small_u16),
    st.builds(Rflush, tag=small_u16),
    st.builds(
        Twalk,
        fid=small_u32,
        newfid=small_u32,
        wname=st.lists(text, max_size=16).map(tuple),
        tag=small_u16,
    ),
    st.builds(Rwalk, wqid=st.lists(qids, max_size=16).map(tuple), tag=small_u16),
    st.builds(Topen, fid=small_u32, mode=small_u8, tag=small_u16),
    st.builds(Ropen, qid=qids, iounit=small_u32, tag=small_u16),
    st.builds(Tcreate, fid=small_u32, name=text, perm=small_u32, mode=small_u8, tag=small_u16),
    st.builds(Rcreate, qid=qids, iounit=small_u32, tag=small_u16),
    st.builds(Tread, fid=small_u32, offset=small_i64, count=small_u32, tag=small_u16),
    st.builds(Rread, data=blob, tag=small_u16),
    st.builds(Twrite, fid=small_u32, data=blob, offset=small_i64, tag=small_u16),
    st.builds(Rwrite, count=small_u32, tag=small_u16),
    st.builds(Tclunk, fid=small_u32, tag=small_u16),
    st.builds(Rclunk, tag=small_u16),
    st.builds(Tremove, fid=small_u32, tag=small_u16),
    st.builds(Rremove, tag=small_u16),
    st.builds(Tstat, fid=small_u32, tag=small_u16),
    st.builds(Rstat, stat=dirs, tag=small_u16),
    st.builds(Twstat, fid=small_u32, stat=dirs, tag=small_u16),
    st.builds(Rwstat, tag=small_u16),
)


@pytest.mark.native
@given(message=messages)
@settings(max_examples=300)
def test_message_roundtrip_property(message, native_so):
    assert decode_message(encode_message(message)) == message


@pytest.mark.native
@given(entry=dirs)
@settings(max_examples=300)
def test_dir_roundtrip_property(entry, native_so):
    assert Dir.from_bytes(entry.to_bytes()) == entry


@pytest.mark.native
@given(data=blob)
@settings(max_examples=100)
def test_binary_payloads_preserve_exact_bytes(data, native_so):
    assert decode_message(Rread(data=data).to_bytes()).data == data
    assert decode_message(Twrite(fid=1, data=data).to_bytes()).data == data
