# py9p

Pythonic 9P2000 messages and client helpers backed by plan9port's C wire
codec. The Python API is intentionally small: dataclasses model the protocol,
`to_bytes()` uses the native codec, and `Client` gives scripts a synchronous
multiplexed request/response wrapper.

## Quick API

```python
from py9p import Tversion, Twalk, decode_message

wire = Tversion(msize=8192).to_bytes()
assert decode_message(wire) == Tversion(msize=8192)

walk = Twalk(fid=0, newfid=1, wname=("usr", "glenda", "notes"))
assert decode_message(walk.to_bytes()) == walk
```

Stats are first-class dataclasses too:

```python
from py9p import DMDIR, DMEXEC, DMREAD, Dir, Qid

entry = Dir(
    qid=Qid(type=0x80, vers=7, path=42),
    mode=int(DMDIR | DMREAD | DMEXEC),
    length=0,
    name="notes",
    uid="glenda",
    gid="glenda",
    muid="glenda",
)
assert Dir.from_bytes(entry.to_bytes()) == entry
```

For real transports, use the synchronous multiplexed client:

```python
from py9p import Client, OREAD

with Client.connect_tcp("127.0.0.1", 564) as c:
    c.negotiate()
    c.attach(fid=0, uname="glenda")
    c.walk(fid=0, newfid=1, path="usr/glenda/notes")
    c.open(fid=1, mode=int(OREAD))
    data = c.read(fid=1, count=4096)
    c.clunk(fid=1)
```

For a local exported namespace, use drawterm's `exportfs` instead of a Python
server reimplementation:

```python
from py9p import Client, OREAD

with Client.connect_exportfs(drawterm="../drawterm/drawterm", root="/tmp") as c:
    c.negotiate()
    c.attach(fid=0, uname="glenda")
    c.walk(fid=0, newfid=1, path="hello.txt")
    c.open(fid=1, mode=int(OREAD))
    data = c.read(fid=1, count=4096)
```

You can drop down a level whenever you need exact protocol control:

```python
from py9p import Rread, read_message, write_message

write_message(sock, Rread(tag=3, data=b"hello"))
msg = read_message(sock)
```

`Client.rpc()` manages tags by default. Pass `tag=...` only when you need a
specific protocol tag for a low-level probe.

## Scope

This first slice targets 9P2000 message and stat encoding/decoding plus a
small synchronous client with multiplexed tagged RPC. Server-side work should
reuse 9front/drawterm `exportfs`; py9p now exposes a process transport for
drawterm's raw stdio exportfs mode.

Authenticated 9front sessions are in scope, but should come from drawterm's
existing p9any/dp9ik, factotum/secstore, TLS/SSL, and exportfs composition
rather than a Python auth rewrite. The current Python API does not yet expose
that authenticated session binding. 9P2000.u extensions are also not yet
implemented.

The native library is built from the vendored plan9port converters:
`convM2S`, `convS2M`, `convM2D`, and `convD2M`. py9p adds only a small C shim
with fixed-width structs so Python does not depend on plan9port's internal C
struct ABI.

## Development

```bash
(cd vendor && ./build.sh)
python -m pytest
```

The full local gate mirrors py-libtab's style:

```bash
./run-all-tests.sh
./run-all-tests.sh all
```
