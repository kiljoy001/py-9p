from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from py9p import (
    DMDIR,
    DMEXEC,
    DMREAD,
    QTDIR,
    Client,
    Dir,
    Qid,
    Tversion,
    Twalk,
    decode_message,
)


def main() -> None:
    version = Tversion(msize=8192)
    print("1. message object")
    print("   ", version)
    print("2. native wire bytes")
    print("   ", version.to_bytes().hex())
    print("3. decoded message")
    print("   ", decode_message(version.to_bytes()))

    walk = Twalk(fid=0, newfid=1, wname=("usr", "glenda", "notes"))
    print("4. walk request")
    print("   ", walk)

    entry = Dir(
        qid=Qid(type=int(QTDIR), vers=7, path=42),
        mode=int(DMDIR | DMREAD | DMEXEC),
        name="notes",
        uid="glenda",
        gid="glenda",
        muid="glenda",
    )
    print("5. stat round-trip")
    print("   ", Dir.from_bytes(entry.to_bytes()))

    print("6. client shape")
    print("   ", "Client.connect_tcp(...).negotiate(); attach(); walk(); open(); read()")
    assert Client is not None


if __name__ == "__main__":
    main()
