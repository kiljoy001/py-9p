from __future__ import annotations

import pytest

from py9p import (
    DMDIR,
    DMEXEC,
    DMREAD,
    QTDIR,
    CodecError,
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
    message_size,
)


def sample_dir() -> Dir:
    return Dir(
        type=0,
        dev=0,
        qid=Qid(type=int(QTDIR), vers=7, path=42),
        mode=int(DMDIR | DMREAD | DMEXEC),
        atime=1,
        mtime=2,
        length=0,
        name="notes",
        uid="glenda",
        gid="glenda",
        muid="glenda",
    )


MESSAGES = [
    Tversion(msize=8192),
    Rversion(msize=8192),
    Tauth(afid=99, uname="glenda", aname="main", tag=1),
    Rauth(aqid=Qid(type=0, vers=1, path=2), tag=1),
    Tattach(fid=0, afid=99, uname="glenda", aname="", tag=2),
    Rattach(qid=Qid(type=int(QTDIR), vers=1, path=2), tag=2),
    Rerror(ename="not found", tag=3),
    Tflush(oldtag=2, tag=4),
    Rflush(tag=4),
    Twalk(fid=0, newfid=1, wname=("usr", "glenda", "notes"), tag=5),
    Rwalk(wqid=(Qid(type=int(QTDIR), vers=1, path=3), Qid(type=0, vers=2, path=4)), tag=5),
    Topen(fid=1, mode=0, tag=6),
    Ropen(qid=Qid(type=0, vers=1, path=5), iounit=4096, tag=6),
    Tcreate(fid=1, name="new.txt", perm=0o666, mode=1, tag=7),
    Rcreate(qid=Qid(type=0, vers=1, path=6), iounit=4096, tag=7),
    Tread(fid=1, offset=8, count=128, tag=8),
    Rread(data=b"hello\x00world", tag=8),
    Twrite(fid=1, offset=8, data=b"hello\x00world", tag=9),
    Rwrite(count=11, tag=9),
    Tclunk(fid=1, tag=10),
    Rclunk(tag=10),
    Tremove(fid=1, tag=11),
    Rremove(tag=11),
    Tstat(fid=1, tag=12),
    Rstat(stat=sample_dir(), tag=12),
    Twstat(fid=1, stat=sample_dir(), tag=13),
    Rwstat(tag=13),
]


@pytest.mark.native
@pytest.mark.parametrize("message", MESSAGES)
def test_message_roundtrip(message, native_so):
    wire = encode_message(message)
    assert len(wire) == message_size(message)
    assert decode_message(wire) == message


@pytest.mark.native
def test_tversion_pinned_wire_vector(native_so):
    assert Tversion(msize=8192).to_bytes().hex() == (
        "1300000064ffff002000000600395032303030"
    )


@pytest.mark.native
def test_dir_roundtrip(native_so):
    entry = sample_dir()
    assert Dir.from_bytes(entry.to_bytes()) == entry


@pytest.mark.native
def test_empty_walk_is_valid(native_so):
    walk = Twalk(fid=7, newfid=8, wname=(), tag=14)
    assert decode_message(walk.to_bytes()) == walk


@pytest.mark.native
def test_rstat_with_raw_stat_bytes_roundtrips_as_dir(native_so):
    entry = sample_dir()
    msg = Rstat(stat=entry.to_bytes(), tag=15)
    assert decode_message(msg.to_bytes()) == Rstat(stat=entry, tag=15)


@pytest.mark.native
def test_decode_rejects_truncated_message(native_so):
    with pytest.raises(CodecError):
        decode_message(b"\x13\x00\x00")


@pytest.mark.native
def test_decode_rejects_wrong_size_field(native_so):
    wire = bytearray(Tversion(msize=8192).to_bytes())
    wire[0] = 0x12
    with pytest.raises(CodecError):
        decode_message(bytes(wire))
