#!/usr/bin/env bash
# SFW test runner — works both as a `bazel test` sh_test target AND when
# invoked directly from the command line.
#
# Usage (direct):  ./tests/run_tests_bazel.sh
# Usage (Bazel):   bazel test //:test_sfw
#
# TAP interface creation and raw socket access both require elevated
# privileges, so pytest is invoked via sudo.
set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the sfw binary and test files
# ---------------------------------------------------------------------------
if [[ -n "${TEST_SRCDIR:-}" && -n "${TEST_WORKSPACE:-}" ]]; then
    # Running inside Bazel sandbox — use the runfiles tree
    RUNFILES="${TEST_SRCDIR}/${TEST_WORKSPACE}"
    SFW_BIN="${RUNFILES}/sfw"
    TESTS_DIR="${RUNFILES}/tests"
else
    # Direct invocation — locate relative to this script
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
    SFW_BIN="${SFW_BIN:-${PROJECT_ROOT}/bazel-bin/sfw}"
    TESTS_DIR="${SCRIPT_DIR}"
fi

export SFW_BIN
export PYTHONPATH="${TESTS_DIR}:${PYTHONPATH:-}"

# ---------------------------------------------------------------------------
# Run pytest as root (required for ip tuntap and raw sockets)
# -p no:cacheprovider avoids writing .pytest_cache into read-only runfiles
# ---------------------------------------------------------------------------
exec sudo \
    SFW_BIN="${SFW_BIN}" \
    PYTHONPATH="${PYTHONPATH}" \
    python3 -m pytest \
        "${TESTS_DIR}/test_sfw.py" \
        -p no:cacheprovider \
        -s -v
