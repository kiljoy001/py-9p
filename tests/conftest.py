from __future__ import annotations

import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_SO = os.path.join(ROOT, "vendor", "libpy9p.so")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "native: requires vendor/libpy9p.so")
    config.addinivalue_line("markers", "remote: requires an external 9P server")


@pytest.fixture(scope="session")
def native_so() -> str:
    if not os.path.exists(NATIVE_SO):
        pytest.skip("vendor/libpy9p.so not built; run vendor/build.sh")
    return NATIVE_SO
