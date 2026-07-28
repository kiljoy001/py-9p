from __future__ import annotations

import ctypes

import pytest

from py9p import native

EXPECTED = {
    "py9p_lasterror": (ctypes.c_char_p, []),
    "py9p_clear_error": (None, []),
    "py9p_size_fcall": (
        ctypes.c_int,
        [native._NonNullFcallP, native._NonNullU32P],
    ),
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
    "py9p_size_dir": (
        ctypes.c_int,
        [native._NonNullDirP, native._NonNullU32P],
    ),
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


@pytest.fixture(scope="module")
def lib(native_so):
    native._lib = None
    return native._get_lib()


@pytest.mark.native
@pytest.mark.parametrize("name", EXPECTED)
def test_restype(lib, name):
    expected, _ = EXPECTED[name]
    assert getattr(lib, name).restype == expected


@pytest.mark.native
@pytest.mark.parametrize("name", EXPECTED)
def test_argtypes(lib, name):
    _, expected = EXPECTED[name]
    assert getattr(lib, name).argtypes == expected


def test_nonnull_pointer_guards_reject_none():
    with pytest.raises(native.CodecError):
        native._NonNullU8P.from_param(None)
