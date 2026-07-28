# Testing py9p

py9p copies the py-libtab testing shape and applies it to 9P wire safety.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[test,security,dev]"
(cd vendor && ./build.sh)
./run-all-tests.sh
./run-all-tests.sh all
```

## Layers

| Layer | Tool | Purpose |
|---|---|---|
| `build` | gcc | normal and sanitizer native builds |
| `unit` | pytest | examples, codec vectors, client behavior |
| `coverage` | pytest-cov | line coverage report when installed |
| `lint` | ruff | Python style and common bugs |
| `dup` | PMD/CPD | optional copy-paste scan |
| `sast` | bandit | Python static security scan |
| `audit` | pip-audit | dependency advisories |
| `fuzz` | atheris + ASan replay | malformed 9P packet/stat memory safety |
| `mutation` | mutmut | checks whether tests really assert behavior |

## Native Codec Checks

The core invariants are:

- every supported message round-trips through plan9port C;
- stat buffers round-trip as `Dir`;
- malformed packets raise `CodecError` or `ProtocolError`, never crash;
- ctypes signatures are pinned so pointer/length arguments do not drift;
- short fuzz campaigns can run in CI, and longer campaigns can reuse the same
  harnesses locally.

## Mutation Scope

Exact local exception wording is treated as diagnostic text, so those lines are
marked with `# pragma: no mutate` in the same style as py-libtab. Protocol
constants, native symbol names, path lookup strings, validation bounds, and FFI
signatures remain mutable and should either be killed by tests or triaged as
real survivors.

## Fuzzing

```bash
tests/fuzz/run.sh fuzz message -atheris_runs=50000
tests/fuzz/run.sh replay message
tests/fuzz/run.sh fuzz dir -atheris_runs=50000
tests/fuzz/run.sh replay dir
```

`fuzz` grows a corpus using the normal build. `replay` feeds that corpus to
the ASan/UBSan build to catch C memory bugs with located sanitizer reports.

## Remote 9front Smoke

The normal suite does not require a networked Plan 9 host. To prove the Python
client against a real 9front server, start a temporary read-only raw `exportfs`
listener on the 9front machine, then point pytest at it:

```rc
aux/listen1 -v tcp!*!59650 exportfs -R -r /
```

```bash
PY9P_9FRONT_HOST=dev9p.rentonsoftworks.coin \
PY9P_9FRONT_PORT=59650 \
PY9P_9FRONT_USER=scott \
PY9P_9FRONT_READ_PATH=lib/namespace \
python -m pytest -q tests/test_remote_9front.py
```

The read tests negotiate `9P2000`, attach, walk to the file, open it, read
bytes, clunk the fid, and verify the clunked fid is no longer usable. They
also send several tagged `Tread` messages before reading any replies, then
validate the returned data by tag.

For a writable smoke, serve a temporary in-memory filesystem from 9front:

```rc
aux/listen1 -v tcp!*!59655 ramfs -i
```

```bash
PY9P_9FRONT_WRITE=1 \
PY9P_9FRONT_WRITE_HOST=dev9p.rentonsoftworks.coin \
PY9P_9FRONT_WRITE_PORT=59655 \
PY9P_9FRONT_USER=scott \
python -m pytest -q tests/test_remote_9front.py
```

The write tests create unique files, write bytes, clunk, walk back to the
files, read the payloads, and remove them. They also send several tagged
`Twrite` messages before reading any replies. Set `PY9P_9FRONT_WRITE_DIR` to
test a writable subdirectory instead of the served root.

These remote smokes intentionally exercise raw 9P/exportfs behavior, not
authenticated CPU service login. Authenticated 9front coverage should reuse the
drawterm auth path: p9any/dp9ik negotiation, factotum/secstore key handling,
TLS/SSL wrapping, then `exportfs` on the authenticated fd.
