#!/usr/bin/env bash
# Export the request file (.github/sed-verify/request.txt) as environment
# variables for the harness. Workflow-dispatch inputs win when they are set.
set -uo pipefail

file="${GITHUB_WORKSPACE:-.}/.github/sed-verify/request.txt"
dispatch_patches="$1"
dispatch_extra="$2"
dispatch_tests="$3"
dispatch_scale="$4"

get() { # $1 = key
  [ -f "$file" ] || return 0
  grep -E "^$1=" "$file" | head -1 | cut -d= -f2- || true
}

patches="$dispatch_patches"; [ -n "$patches" ] || patches="$(get patches)"
extra="$dispatch_extra";     [ -n "$extra" ]   || extra="$(get extra_shas)"
tests="$dispatch_tests";     [ -n "$tests" ]   || tests="$(get check_tests)"
[ -n "$tests" ] || tests=1
scale="$dispatch_scale";     [ -n "$scale" ]   || scale="$(get scale)"
[ -n "$scale" ] || scale=100000

{
  echo "PATCHES=$patches"
  echo "EXTRA_SHAS=$extra"
  echo "CHECK_TESTS=$tests"
  echo "SCALE=$scale"
} >> "$GITHUB_ENV"

echo "request: patches='$patches' extra='$extra' check_tests=$tests scale=$scale"
