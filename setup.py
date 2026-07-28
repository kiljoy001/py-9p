"""Build hook for the ctypes native codec.

py9p is a ctypes binding, not a CPython extension module. The dummy
Extension forces a platform wheel tag and lets build_ext run vendor/build.sh,
which compiles plan9port's 9P converter C plus a narrow py9p shim into
libpy9p.so.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

HERE = os.path.dirname(os.path.abspath(__file__))


class BuildPy9pSo(build_ext):
    def run(self) -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimeError(
                "py9p is currently tested for Linux x86_64 source builds and wheels only; "
                f"building from source on {sys.platform!r} is not supported yet."
            )

        build_sh = os.path.join(HERE, "vendor", "build.sh")
        if not os.path.exists(build_sh):
            raise RuntimeError(f"vendor/build.sh missing at {build_sh}")

        subprocess.run(["bash", build_sh], check=True, cwd=HERE)
        built_so = os.path.join(HERE, "vendor", "libpy9p.so")
        if not os.path.exists(built_so):
            raise RuntimeError("vendor/build.sh did not produce vendor/libpy9p.so")

        dest_dir = os.path.join(self.build_lib, "py9p")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, "libpy9p.so")
        shutil.copy2(built_so, dest)
        self.announce(f"placed native library at {dest}", level=2)


setup(
    ext_modules=[Extension(name="py9p._native_placeholder", sources=[])],
    cmdclass={"build_ext": BuildPy9pSo},
)
