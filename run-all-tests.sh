#!/bin/bash
# Single test entry point for py9p.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ -n "${PYTHON:-}" ]; then
    PY="$PYTHON"
    BIN="$(dirname "$PY")"
elif [ -x "$ROOT/.venv/bin/python" ]; then
    PY="$ROOT/.venv/bin/python"
    BIN="$ROOT/.venv/bin"
else
    PY="$(command -v python3)"
    BIN="$(dirname "$PY")"
fi

GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
declare -a RESULTS=()
FAILED=0

hdr()  { printf "\n${BOLD}=== %s ===${OFF}\n" "$1"; }
pass() { RESULTS+=("${GREEN}PASS${OFF}  $1"); }
skip() { RESULTS+=("${YEL}SKIP${OFF}  $1 ${YEL}($2)${OFF}"); printf "${YEL}skipping %s: %s${OFF}\n" "$1" "$2"; }
fail() { RESULTS+=("${RED}FAIL${OFF}  $1"); FAILED=1; }

have_bin() { command -v "$1" >/dev/null 2>&1; }
have_py()  { "$PY" -c "import $1" >/dev/null 2>&1; }
venv_or_path() {
    if [ -x "$BIN/$1" ]; then
        printf '%s\n' "$BIN/$1"
    else
        command -v "$1"
    fi
}

layer_build() {
    hdr "build (vendor/libpy9p.so + libpy9p-asan.so)"
    if ! have_bin gcc; then skip build "gcc not found"; return; fi
    ( cd "$ROOT/vendor" && ./build.sh >/dev/null 2>&1 ) \
        && ( cd "$ROOT/vendor" && SANITIZE=1 ./build.sh >/dev/null 2>&1 ) \
        && { echo "built native libraries"; pass build; } \
        || fail build
}

ensure_built() {
    [ -f "$ROOT/vendor/libpy9p.so" ] || layer_build
}

layer_unit() {
    hdr "unit + integration (pytest)"
    ensure_built
    if ! have_py pytest; then fail unit; echo "pytest not installed"; return; fi
    if "$PY" -m pytest -q; then pass unit; else fail unit; fi
}

layer_coverage() {
    hdr "coverage (pytest --cov)"
    ensure_built
    if ! have_py pytest_cov; then skip coverage "pytest-cov not installed"; return; fi
    if "$PY" -m pytest -q --cov=py9p --cov-report=term-missing; then pass coverage; else fail coverage; fi
}

layer_lint() {
    hdr "lint (ruff)"
    local ruff_bin
    ruff_bin="$(venv_or_path ruff 2>/dev/null || true)"
    if [ -z "$ruff_bin" ]; then skip lint "ruff not installed"; return; fi
    if "$ruff_bin" check py9p tests examples; then pass lint; else fail lint; fi
}

layer_dup() {
    hdr "duplication (PMD / CPD)"
    if ! have_bin pmd; then skip dup "pmd not found"; return; fi
    local out
    out="$(pmd cpd --minimum-tokens 40 --language python --dir py9p --format text 2>/dev/null || true)"
    printf '%s\n' "$out"
    pass dup
}

layer_sast() {
    hdr "SAST (bandit)"
    local bandit_bin
    bandit_bin="$(venv_or_path bandit 2>/dev/null || true)"
    if [ -z "$bandit_bin" ]; then skip sast "bandit not installed"; return; fi
    if "$bandit_bin" -r py9p -q; then pass sast; else fail sast; fi
}

layer_audit() {
    hdr "dependency audit (pip-audit)"
    local audit_bin
    audit_bin="$(venv_or_path pip-audit 2>/dev/null || true)"
    if [ -z "$audit_bin" ]; then skip audit "pip-audit not installed"; return; fi
    if "$audit_bin" --skip-editable; then pass audit; else fail audit; fi
}

layer_fuzz() {
    hdr "fuzz (atheris) + ASan replay"
    if ! have_py atheris; then skip fuzz "atheris not installed"; return; fi
    ensure_built
    local ok=1
    for target in message dir; do
        echo "-- fuzz $target --"
        "$ROOT/tests/fuzz/run.sh" fuzz "$target" -atheris_runs=10000 >/dev/null 2>&1 || ok=0
    done
    if [ -f "$ROOT/vendor/libpy9p-asan.so" ] && have_bin gcc; then
        for target in message dir; do
            echo "-- ASan replay $target --"
            local rep
            rep="$("$ROOT/tests/fuzz/run.sh" replay "$target" 2>&1 || true)"
            if echo "$rep" | grep -qE "ERROR: AddressSanitizer|runtime error:"; then
                echo "$rep" | tail -40
                ok=0
            fi
        done
    else
        echo "(ASan replay skipped; libpy9p-asan.so or gcc missing)"
    fi
    [ "$ok" = 1 ] && pass fuzz || fail fuzz
}

layer_mutation() {
    hdr "mutation (mutmut)"
    if ! have_py mutmut; then skip mutation "mutmut not installed"; return; fi
    ensure_built
    rm -rf mutants .mutmut-cache
    timeout 30 "$PY" -m mutmut run --max-children 1 >/dev/null 2>&1 || true
    [ -d mutants ] && ln -sf ../vendor mutants/vendor
    "$PY" -m mutmut run >/dev/null 2>&1 || true
    local results counts bad bad_count
    results="$("$PY" -m mutmut results --all true 2>/dev/null || true)"
    if [ -z "$results" ]; then
        echo "mutmut produced no result set"
        fail mutation
        return
    fi
    counts="$(
        printf '%s\n' "$results" \
            | sed -n 's/^.*: \([a-z ][a-z ]*\)$/\1/p' \
            | sort \
            | uniq -c \
            || true
    )"
    printf '%s\n' "$counts"
    bad="$(printf '%s\n' "$results" | grep -Ev ': killed$' || true)"
    if [ -z "$bad" ]; then
        rm -rf mutants .mutmut-cache
        pass mutation
    else
        printf '%s\n' "$bad" | head -50
        bad_count="$(printf '%s\n' "$bad" | sed '/^$/d' | wc -l)"
        echo "$bad_count mutants were not killed"
        fail mutation
    fi
}

ALL_LAYERS=(build unit coverage lint dup sast audit fuzz mutation)
STANDARD=(unit lint dup sast audit)

if [ "${1:-}" = "--list" ]; then
    printf '%s\n' "${ALL_LAYERS[@]}"
    exit 0
fi

case "${1:-standard}" in
    ""|standard) SELECTED=("${STANDARD[@]}") ;;
    all)         SELECTED=("${ALL_LAYERS[@]}") ;;
    *)           SELECTED=("$@") ;;
esac

for layer in "${SELECTED[@]}"; do
    if declare -f "layer_$layer" >/dev/null; then
        "layer_$layer"
    else
        echo "${RED}unknown layer: $layer${OFF} (see --list)"
        FAILED=1
    fi
done

hdr "summary"
printf '%s\n' "${RESULTS[@]}"
if [ "$FAILED" = 0 ]; then
    printf "\n${GREEN}${BOLD}all selected layers passed${OFF}\n"
    exit 0
fi
printf "\n${RED}${BOLD}one or more layers failed${OFF}\n"
exit 1
