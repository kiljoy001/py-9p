from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RUN = os.path.join(HERE, "fuzz", "run.sh")
ASAN_SO = os.path.join(ROOT, "vendor", "libpy9p-asan.so")
IN_MUTANTS_COPY = f"{os.sep}mutants{os.sep}" in os.path.abspath(__file__)


pytestmark = [
    pytest.mark.skipif(importlib.util.find_spec("atheris") is None, reason="atheris not installed"),
    pytest.mark.skipif(IN_MUTANTS_COPY, reason="integration fuzz harness; not useful per mutant"),
]


@pytest.mark.native
@pytest.mark.parametrize("target", ["message", "dir"])
def test_short_fuzz_runs_clean(target, native_so):
    env = os.environ.copy()
    env["PYTHON"] = sys.executable
    proc = subprocess.run(
        ["bash", RUN, "fuzz", target, "-atheris_runs=1000"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.native
@pytest.mark.skipif(not os.path.exists(ASAN_SO), reason="ASan build not present")
@pytest.mark.parametrize("target", ["message", "dir"])
def test_asan_replay_clean(target, native_so):
    env = os.environ.copy()
    env["PYTHON"] = sys.executable
    proc = subprocess.run(
        ["bash", RUN, "replay", target],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert "ERROR: AddressSanitizer" not in proc.stderr
    assert proc.returncode == 0, proc.stdout + proc.stderr
