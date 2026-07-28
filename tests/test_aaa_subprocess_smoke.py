"""Crash-smoke tests that run risky native paths in a child process."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_child(script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["PY9P_SO"] = os.path.join(ROOT, "vendor", "libpy9p.so")
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.native
def test_happy_paths_survive_in_subprocess(native_so):
    proc = _run_child(
        """
        from py9p import *

        assert decode_message(Tversion(msize=8192).to_bytes()) == Tversion(msize=8192)
        payload = b"a\\x00b\\x00c"
        assert decode_message(Twrite(fid=1, data=payload).to_bytes()).data == payload

        entry = Dir(qid=Qid(type=128, vers=1, path=2), name="n", uid="u", gid="g", muid="m")
        assert Dir.from_bytes(entry.to_bytes()) == entry
        print("ok")
        """
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout


@pytest.mark.native
def test_guard_probes_survive_in_subprocess(native_so):
    proc = _run_child(
        """
        from py9p import *
        from py9p import native

        for action in (
            lambda: decode_message(b""),
            lambda: Dir.from_bytes(b""),
            lambda: Rread(data="bad").to_bytes(),
            lambda: Twalk(fid=0, newfid=1, wname=("a\\x00b",)).to_bytes(),
            lambda: native._NonNullU8P.from_param(None),
        ):
            try:
                action()
            except Exception:
                pass
            else:
                raise AssertionError("guard probe unexpectedly succeeded")
        print("ok")
        """
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout
