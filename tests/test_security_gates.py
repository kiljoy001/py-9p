from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

BANDIT_IN_VENV = os.path.join(os.path.dirname(sys.executable), "bandit")
BANDIT = BANDIT_IN_VENV if os.path.exists(BANDIT_IN_VENV) else (shutil.which("bandit") or "")


@pytest.mark.skipif(not BANDIT, reason="bandit not installed")
def test_bandit_reports_no_issues():
    proc = subprocess.run(
        [BANDIT, "-r", "py9p", "-q"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
