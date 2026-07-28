from __future__ import annotations

import ctypes

import pytest

from py9p import (
    Dir,
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


def _assert_raw_qid(raw_qid, qid: Qid) -> None:
    assert raw_qid.type == qid.type
    assert raw_qid.vers == qid.vers
    assert raw_qid.path == qid.path


@pytest.mark.native
def test_message_to_raw_preserves_zero_boundary_fields(native_so):
    qid = Qid(type=0, vers=0, path=0)
    entry = Dir(qid=qid, name="", uid="", gid="", muid="")
    stat_wire = entry.to_bytes()

    raw, _ = native._message_to_raw(Tversion(msize=0, version="", tag=0))
    assert (raw.type, raw.tag, raw.msize, raw.version) == (
        int(MessageType.TVERSION),
        0,
        0,
        b"",
    )

    raw, _ = native._message_to_raw(Rversion(msize=0, version="", tag=0))
    assert (raw.type, raw.tag, raw.msize, raw.version) == (
        int(MessageType.RVERSION),
        0,
        0,
        b"",
    )

    raw, _ = native._message_to_raw(Tauth(afid=0, uname="", aname="", tag=0))
    assert (raw.type, raw.tag, raw.afid, raw.uname, raw.aname) == (
        int(MessageType.TAUTH),
        0,
        0,
        b"",
        b"",
    )

    raw, _ = native._message_to_raw(Rauth(aqid=qid, tag=0))
    assert (raw.type, raw.tag) == (int(MessageType.RAUTH), 0)
    _assert_raw_qid(raw.aqid, qid)

    raw, _ = native._message_to_raw(Tattach(fid=0, afid=0, uname="", aname="", tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.afid, raw.uname, raw.aname) == (
        int(MessageType.TATTACH),
        0,
        0,
        0,
        b"",
        b"",
    )

    raw, _ = native._message_to_raw(Rattach(qid=qid, tag=0))
    assert (raw.type, raw.tag) == (int(MessageType.RATTACH), 0)
    _assert_raw_qid(raw.qid, qid)

    raw, _ = native._message_to_raw(Rerror(ename="", tag=0))
    assert (raw.type, raw.tag, raw.ename) == (int(MessageType.RERROR), 0, b"")

    raw, _ = native._message_to_raw(Tflush(oldtag=0, tag=0))
    assert (raw.type, raw.tag, raw.oldtag) == (int(MessageType.TFLUSH), 0, 0)

    raw, _ = native._message_to_raw(Rflush(tag=0))
    assert (raw.type, raw.tag) == (int(MessageType.RFLUSH), 0)

    raw, _ = native._message_to_raw(Twalk(fid=0, newfid=0, wname=("", "a"), tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.newfid, raw.nwname) == (
        int(MessageType.TWALK),
        0,
        0,
        0,
        2,
    )
    assert (raw.wname[0], raw.wname[1]) == (b"", b"a")

    raw, _ = native._message_to_raw(Rwalk(wqid=(qid,), tag=0))
    assert (raw.type, raw.tag, raw.nwqid) == (int(MessageType.RWALK), 0, 1)
    _assert_raw_qid(raw.wqid[0], qid)

    raw, _ = native._message_to_raw(Topen(fid=0, mode=0, tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.mode) == (int(MessageType.TOPEN), 0, 0, 0)

    raw, _ = native._message_to_raw(Ropen(qid=qid, iounit=0, tag=0))
    assert (raw.type, raw.tag, raw.iounit) == (int(MessageType.ROPEN), 0, 0)
    _assert_raw_qid(raw.qid, qid)

    raw, _ = native._message_to_raw(Tcreate(fid=0, name="", perm=0, mode=0, tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.name, raw.perm, raw.mode) == (
        int(MessageType.TCREATE),
        0,
        0,
        b"",
        0,
        0,
    )

    raw, _ = native._message_to_raw(Rcreate(qid=qid, iounit=0, tag=0))
    assert (raw.type, raw.tag, raw.iounit) == (int(MessageType.RCREATE), 0, 0)
    _assert_raw_qid(raw.qid, qid)

    raw, _ = native._message_to_raw(Tread(fid=0, offset=0, count=0, tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.offset, raw.count) == (
        int(MessageType.TREAD),
        0,
        0,
        0,
        0,
    )

    raw, _ = native._message_to_raw(Rread(data=b"", tag=0))
    assert (raw.type, raw.tag, raw.count) == (int(MessageType.RREAD), 0, 0)
    assert ctypes.string_at(raw.data, raw.count) == b""

    raw, _ = native._message_to_raw(Twrite(fid=0, offset=0, data=b"", tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.offset, raw.count) == (
        int(MessageType.TWRITE),
        0,
        0,
        0,
        0,
    )
    assert ctypes.string_at(raw.data, raw.count) == b""

    raw, _ = native._message_to_raw(Rwrite(count=0, tag=0))
    assert (raw.type, raw.tag, raw.count) == (int(MessageType.RWRITE), 0, 0)

    raw, _ = native._message_to_raw(Tclunk(fid=0, tag=0))
    assert (raw.type, raw.tag, raw.fid) == (int(MessageType.TCLUNK), 0, 0)

    raw, _ = native._message_to_raw(Rclunk(tag=0))
    assert (raw.type, raw.tag) == (int(MessageType.RCLUNK), 0)

    raw, _ = native._message_to_raw(Tremove(fid=0, tag=0))
    assert (raw.type, raw.tag, raw.fid) == (int(MessageType.TREMOVE), 0, 0)

    raw, _ = native._message_to_raw(Rremove(tag=0))
    assert (raw.type, raw.tag) == (int(MessageType.RREMOVE), 0)

    raw, _ = native._message_to_raw(Tstat(fid=0, tag=0))
    assert (raw.type, raw.tag, raw.fid) == (int(MessageType.TSTAT), 0, 0)

    raw, _ = native._message_to_raw(Rstat(stat=stat_wire, tag=0))
    assert (raw.type, raw.tag, raw.nstat) == (int(MessageType.RSTAT), 0, len(stat_wire))
    assert ctypes.string_at(raw.stat, raw.nstat) == stat_wire

    raw, _ = native._message_to_raw(Twstat(fid=0, stat=stat_wire, tag=0))
    assert (raw.type, raw.tag, raw.fid, raw.nstat) == (
        int(MessageType.TWSTAT),
        0,
        0,
        len(stat_wire),
    )
    assert ctypes.string_at(raw.stat, raw.nstat) == stat_wire

    raw, _ = native._message_to_raw(Rwstat(tag=0))
    assert (raw.type, raw.tag) == (int(MessageType.RWSTAT), 0)


@pytest.mark.native
def test_message_to_raw_preserves_max_boundary_fields(native_so):
    qid = Qid(type=0xFF, vers=0xFFFFFFFF, path=0xFFFFFFFFFFFFFFFF)

    raw, _ = native._message_to_raw(Tversion(msize=0xFFFFFFFF, version="9P2000", tag=0xFFFF))
    assert (raw.tag, raw.msize, raw.version) == (0xFFFF, 0xFFFFFFFF, b"9P2000")

    raw, _ = native._message_to_raw(Tflush(oldtag=0xFFFF, tag=0xFFFF))
    assert (raw.tag, raw.oldtag) == (0xFFFF, 0xFFFF)

    raw, _ = native._message_to_raw(Tattach(fid=0xFFFFFFFF, afid=0xFFFFFFFF, uname="u", tag=1))
    assert (raw.fid, raw.afid, raw.uname, raw.aname) == (0xFFFFFFFF, 0xFFFFFFFF, b"u", b"")

    raw, _ = native._message_to_raw(Rattach(qid=qid, tag=1))
    _assert_raw_qid(raw.qid, qid)

    raw, _ = native._message_to_raw(Topen(fid=0xFFFFFFFF, mode=0xFF, tag=1))
    assert (raw.fid, raw.mode) == (0xFFFFFFFF, 0xFF)

    raw, _ = native._message_to_raw(
        Tcreate(fid=0xFFFFFFFF, name="n", perm=0xFFFFFFFF, mode=0xFF, tag=1)
    )
    assert (raw.fid, raw.name, raw.perm, raw.mode) == (0xFFFFFFFF, b"n", 0xFFFFFFFF, 0xFF)

    raw, _ = native._message_to_raw(
        Tread(fid=0xFFFFFFFF, offset=0x7FFFFFFFFFFFFFFF, count=0xFFFFFFFF, tag=1)
    )
    assert (raw.fid, raw.offset, raw.count) == (
        0xFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
        0xFFFFFFFF,
    )

    raw, _ = native._message_to_raw(Rwrite(count=0xFFFFFFFF, tag=1))
    assert raw.count == 0xFFFFFFFF


@pytest.mark.native
def test_dir_to_raw_preserves_zero_and_max_boundary_fields(native_so):
    zero_qid = Qid(type=0, vers=0, path=0)
    zero_entry = Dir(qid=zero_qid, name="", uid="", gid="", muid="")
    raw, _ = native._dir_to_raw(zero_entry)
    assert (raw.type, raw.dev, raw.mode, raw.atime, raw.mtime, raw.length) == (
        0,
        0,
        0,
        0,
        0,
        0,
    )
    assert (raw.name, raw.uid, raw.gid, raw.muid) == (b"", b"", b"", b"")
    _assert_raw_qid(raw.qid, zero_qid)

    max_qid = Qid(type=0xFF, vers=0xFFFFFFFF, path=0xFFFFFFFFFFFFFFFF)
    max_entry = Dir(
        type=0xFFFF,
        dev=0xFFFFFFFF,
        qid=max_qid,
        mode=0xFFFFFFFF,
        atime=0xFFFFFFFF,
        mtime=0xFFFFFFFF,
        length=0x7FFFFFFFFFFFFFFF,
        name="n",
        uid="u",
        gid="g",
        muid="m",
    )
    raw, _ = native._dir_to_raw(max_entry)
    assert (raw.type, raw.dev, raw.mode, raw.atime, raw.mtime, raw.length) == (
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    )
    assert (raw.name, raw.uid, raw.gid, raw.muid) == (b"n", b"u", b"g", b"m")
    _assert_raw_qid(raw.qid, max_qid)
