from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings
from hypothesis import strategies as st

from py9p import NOTAG, Client, ProtocolError, Rread, Rversion, Tread, Tversion
from py9p import client as client_mod

path_part = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="/"),
    min_size=0,
    max_size=8,
)


@given(start=st.integers(min_value=0, max_value=NOTAG - 1), steps=st.integers(1, 200))
@settings(max_examples=100)
def test_tag_allocator_property(start, steps):
    client = Client(object())  # type: ignore[arg-type]
    client._next_tag = start

    expected: list[int] = []
    cursor = start
    for _ in range(steps):
        expected.append(cursor)
        cursor = (cursor + 1) & 0xFFFF
        if cursor == NOTAG:
            cursor = 0

    assert [client._tag() for _ in range(steps)] == expected
    assert NOTAG not in expected
    assert client._next_tag == cursor


@given(parts=st.lists(path_part, max_size=20))
@settings(max_examples=100)
def test_path_string_normalization_property(parts):
    path = "/".join(parts)
    assert Client._path_names(path) == tuple(part for part in parts if part and part != ".")


@given(parts=st.lists(path_part, max_size=20))
@settings(max_examples=100)
def test_path_iterable_preservation_property(parts):
    assert Client._path_names(parts) == tuple(parts)


@given(
    start=st.integers(min_value=0, max_value=NOTAG - 1),
    fid=st.integers(min_value=0, max_value=2**32 - 1),
    count=st.integers(min_value=0, max_value=2**16),
)
@settings(max_examples=100)
def test_rpc_assigns_non_version_notag_requests_property(start, fid, count):
    written: list[object] = []
    client = Client(object(), msize=8192)  # type: ignore[arg-type]
    client._next_tag = start

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(client_mod, "write_message", lambda _transport, message: written.append(message))
        monkeypatch.setattr(
            client_mod,
            "read_message",
            lambda _transport, *, max_size: Rread(data=b"", tag=start),
        )

        assert client.rpc(Tread(fid=fid, count=count, tag=NOTAG), Rread) == Rread(
            data=b"",
            tag=start,
        )
    assert written == [Tread(fid=fid, count=count, tag=start)]
    expected_next = (start + 1) & 0xFFFF
    if expected_next == NOTAG:
        expected_next = 0
    assert client._next_tag == expected_next


@given(start=st.integers(min_value=0, max_value=NOTAG - 1), msize=st.integers(7, 65536))
@settings(max_examples=100)
def test_rpc_preserves_tversion_notag_property(start, msize):
    written: list[object] = []
    client = Client(object(), msize=msize)  # type: ignore[arg-type]
    client._next_tag = start

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(client_mod, "write_message", lambda _transport, message: written.append(message))
        monkeypatch.setattr(
            client_mod,
            "read_message",
            lambda _transport, *, max_size: Rversion(msize=msize, tag=NOTAG),
        )

        assert client.rpc(Tversion(msize=msize), Rversion) == Rversion(msize=msize, tag=NOTAG)
    assert written == [Tversion(msize=msize)]
    assert client._next_tag == start


@given(
    request_tag=st.integers(min_value=0, max_value=NOTAG - 1),
    delta=st.integers(min_value=1, max_value=NOTAG - 1),
)
@settings(max_examples=100)
def test_rpc_rejects_mismatched_reply_tags_property(request_tag, delta):
    response_tag = (request_tag + delta) % NOTAG
    client = Client(object())  # type: ignore[arg-type]
    client._next_tag = request_tag
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(client_mod, "write_message", lambda _transport, _message: 0)
        monkeypatch.setattr(
            client_mod,
            "read_message",
            lambda _transport, *, max_size: Rread(data=b"", tag=response_tag),
        )

        with pytest.raises(ProtocolError, match="did not match any outstanding request"):
            client.rpc(Tread(fid=1, count=1), Rread)
