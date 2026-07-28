#!/bin/bash
# Two-phase fuzzing for py9p's untrusted 9P message/stat inputs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
if [ -n "${PYTHON:-}" ]; then
    PY="$PYTHON"
else
    PY="$ROOT/.venv/bin/python"
    [ -x "$PY" ] || PY="$(command -v python3)"
fi
NORMAL_SO="$ROOT/vendor/libpy9p.so"
ASAN_SO="$ROOT/vendor/libpy9p-asan.so"

mode="${1:-fuzz}"; shift || true
target="${1:-message}"; shift || true

case "$target" in
    message) harness="$HERE/fuzz_message.py"; corpus="$HERE/corpus_message" ;;
    dir)     harness="$HERE/fuzz_dir.py";     corpus="$HERE/corpus_dir" ;;
    *) echo "unknown target: $target (use 'message' or 'dir')" >&2; exit 2 ;;
esac

mkdir -p "$corpus"

case "$mode" in
fuzz)
    [ -f "$NORMAL_SO" ] || { echo "missing $NORMAL_SO; run vendor/build.sh" >&2; exit 1; }
    if [ "$#" -eq 0 ]; then set -- -atheris_runs=50000; fi
    exec env PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" PY9P_SO="$NORMAL_SO" \
        "$PY" "$harness" "$@" "$corpus"
    ;;
replay)
    [ -f "$ASAN_SO" ] || { echo "missing $ASAN_SO; run SANITIZE=1 vendor/build.sh" >&2; exit 1; }
    ASAN_RT="$(gcc -print-file-name=libasan.so)"
    exec env \
        PY9P_SO="$ASAN_SO" \
        PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" \
        LD_PRELOAD="$ASAN_RT" \
        ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:handle_segv=1" \
        UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
        "$PY" "$harness" -runs=0 "$corpus"/*
    ;;
*)
    echo "unknown mode: $mode (use 'fuzz' or 'replay')" >&2; exit 2 ;;
esac
