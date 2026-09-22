#!/usr/bin/env bash
# Verification harness for uutils/sed PR #557 ("\U \L \u \l \E" case-conversion escapes).
#
# What it does:
#   1. Builds one or more revisions of uutils/sed (release, same profile family as CI).
#   2. Measures instruction counts with valgrind/callgrind on the `number_fix`
#      workload from benches/sed_bench.rs (the benchmark CodSpeed reports as
#      regressed), plus a case-conversion workload for contrast.
#   3. Optionally applies a patch on top of the PR head and re-measures it, to
#      check that a fix restores instruction-count parity with the base revision.
#   4. Optionally runs fmt/clippy/tests and a GNU sed differential check.
#
# Environment knobs:
#   SED_REPO   git url to clone            (default: dedsec-terminal/sed)
#   BASE_SHA   revision used as baseline   (default: upstream main @ PR time)
#   PR_HEAD    PR head revision            (default: 626ce4f)
#   EXTRA_SHAS space separated extra revisions to measure (default: "")
#   PATCH      path to a .patch file applied on top of PR_HEAD (default: none)
#   SCALE      lines of benchmark input    (default: 100000, same as the bench)
#   CHECK_TESTS 1 to run fmt/clippy/cargo test/gnu-sed diff on the patched tree
set -euo pipefail

SED_REPO="${SED_REPO:-https://github.com/dedsec-terminal/sed.git}"
BASE_SHA="${BASE_SHA:-c46dd6dab61a6a571bf08cb6b333e4fe1f3636c3}"
PR_HEAD="${PR_HEAD:-626ce4f02a3b100e1fddcc584adb4f1be50f9d78}"
EXTRA_SHAS="${EXTRA_SHAS:-}"
PATCH="${PATCH:-}"
SCALE="${SCALE:-100000}"
CHECK_TESTS="${CHECK_TESTS:-0}"

WORK="${WORK:-$HOME/sedwork}"
CARGO_TARGET_DIR="$WORK/target"
export CARGO_TARGET_DIR
mkdir -p "$WORK"
cd "$WORK"

echo "=================== sed PR #557 verification harness ==================="
echo "base=$BASE_SHA head=$PR_HEAD extra='$EXTRA_SHAS' patch=${PATCH:-none} scale=$SCALE"
rustc --version
cargo --version
valgrind --version

# ---------------------------------------------------------------- benchmark data
DATA="$WORK/number_fix.txt"
if [ ! -f "$DATA" ]; then
  python3 - "$DATA" "$SCALE" <<'PY'
import sys
path, scale = sys.argv[1], int(sys.argv[2])
out = []
for i in range(scale):
    euros = i % 10000
    cents = i % 100
    out.append(f"{euros // 1000}.{euros % 1000:03},{cents:02}\n")
open(path, "w").write("".join(out))
PY
fi
echo "benchmark input: $(wc -l < "$DATA") lines, $(wc -c < "$DATA") bytes"

# ---------------------------------------------------------------- repo checkout
REPO="$WORK/sed"
if [ ! -d "$REPO/.git" ]; then
  git clone --quiet "$SED_REPO" "$REPO"
fi
git -C "$REPO" fetch --quiet --all --tags --prune
git -C "$REPO" fetch --quiet "$SED_REPO" "$BASE_SHA" "$PR_HEAD" 2>/dev/null || true

NUM_FIX_SCRIPT='s/\([0-9]\)\.\([0-9]\)/\1\2/g;s/\([0-9]\),\([0-9]\)/\1.\2/g'
CASE_SCRIPT='s/\([0-9]\)\([0-9]*\)/\u\1\L\2/g'

build_variant() { # $1=label $2=sha $3=patch-or-empty
  local label="$1" sha="$2" patch="${3:-}"
  local wt="$WORK/wt-$label"
  rm -rf "$wt"
  git -C "$REPO" worktree prune
  git -C "$REPO" worktree add --quiet --force --detach "$wt" "$sha"
  if [ -n "$patch" ]; then
    git -C "$wt" apply --verbose "$patch"
  fi
  echo "--- building $label ($sha${patch:+ + $(basename "$patch")}) ---"
  ( cd "$wt" && cargo build --quiet --release --bin sed )
  cp "$wt/target/release/sed" "$WORK/sed-$label"
  echo "built $WORK/sed-$label ($(stat -c%s "$WORK/sed-$label") bytes)"
}

measure() { # $1=label $2=script ; prints instruction count
  local label="$1" script="$2"
  local out="$WORK/cg-$label.txt"
  valgrind --tool=callgrind --callgrind-out-file="$WORK/cg-$label.out" \
    --log-file="$out" "$WORK/sed-$label" "$script" "$DATA" > /dev/null 2>&1 || true
  callgrind_annotate --threshold=100 --auto=no "$WORK/cg-$label.out" \
    > "$WORK/annotate-$label.txt" 2>/dev/null || true
  python3 - "$out" <<'PY'
import re, sys
txt = open(sys.argv[1], errors="replace").read()
m = re.search(r"I\s+refs:\s+([\d,]+)", txt)
print(m.group(1).replace(",", "") if m else "0")
PY
}

# ---------------------------------------------------------------- run the matrix
LABELS=()
build_variant base "$BASE_SHA"
LABELS+=(base)
build_variant head "$PR_HEAD"
LABELS+=(head)
if [ -n "$PATCH" ]; then
  build_variant patched "$PR_HEAD" "$PATCH"
  LABELS+=(patched)
fi
for sha in $EXTRA_SHAS; do
  short="$(git -C "$REPO" rev-parse --short "$sha")"
  build_variant "extra-$short" "$sha"
  LABELS+=("extra-$short")
done

echo
echo "=================== results ==================="
printf "%-14s %18s %18s\n" variant "number_fix(Ir)" "case_conv(Ir)"
BASE_NF=""; BASE_CC=""
for label in "${LABELS[@]}"; do
  nf="$(measure "$label" "$NUM_FIX_SCRIPT")"
  cc="$(measure "$label" "$CASE_SCRIPT")"
  printf "%-14s %18s %18s\n" "$label" "$nf" "$cc"
  if [ -z "$BASE_NF" ]; then BASE_NF="$nf"; BASE_CC="$cc"; fi
  echo "$label $nf $cc" >> "$WORK/results.txt"
done

echo
echo "--- deltas vs base (negative = fewer instructions = faster) ---"
awk '/^(base|head|patched|extra)/ {
    nf[$1]=$2; cc[$1]=$3; order[NR]=$1
  }
  END {
    bn=nf["base"]; bc=cc["base"]
    for (i=1;i<=NR;i++) {
      l=order[i]; if (l in seen) continue; seen[l]=1
      printf "%-14s number_fix %+7.2f%%   case_conv %+7.2f%%\n", l,
         (nf[l]-bn)*100.0/bn, (cc[l]-bc)*100.0/bc
    }
  }' "$WORK/results.txt"

echo
echo "--- top instruction deltas by function (base vs head) ---"
python3 - "$WORK/annotate-base.txt" "$WORK/annotate-head.txt" <<'PY' || true
import re, sys

def parse(path):
    d = {}
    for line in open(path, errors="replace"):
        m = re.match(r"\s*([\d,]+)\s+\(\s*[\d.]+%\)\s+(.*)$", line)
        if m:
            d[m.group(2).strip()] = int(m.group(1).replace(",", ""))
    return d

a, b = parse(sys.argv[1]), parse(sys.argv[2])
tot = {}
for k in set(a) | set(b):
    tot[k] = b.get(k, 0) - a.get(k, 0)
rows = sorted(tot.items(), key=lambda kv: -abs(kv[1]))[:25]
print(f"{'delta Ir':>18}  {'base Ir':>16} {'head Ir':>16}  function")
for k, v in rows:
    print(f"{v:>18}  {a.get(k,0):>16} {b.get(k,0):>16}  {k}")
PY

# ---------------------------------------------------------------- optional checks
if [ "$CHECK_TESTS" = "1" ] && [ -n "$PATCH" ]; then
  wt="$WORK/wt-patched"
  echo
  echo "=================== checks on patched tree ==================="
  ( cd "$wt" && cargo fmt --all -- --check && echo "cargo fmt: OK" ) || echo "cargo fmt: FAILED"
  ( cd "$wt" && cargo clippy --all-targets --all-features -- -D warnings > "$WORK/clippy.log" 2>&1 \
      && echo "cargo clippy: OK" ) || { echo "cargo clippy: FAILED"; tail -40 "$WORK/clippy.log"; }
  ( cd "$wt" && cargo test > "$WORK/test.log" 2>&1 && echo "cargo test: OK" ) \
      || { echo "cargo test: FAILED"; grep -E "^(test |failures|error)" "$WORK/test.log" | tail -40; }

  echo
  echo "--- differential check against GNU sed ---"
  printf 'ABC DEF\nabC def\nhello world 123\nMIXed Case Here\n\xc3\xa9t\xc3\xa9 \xc3\x89T\xc3\x89\n' > "$WORK/gnu-in.txt"
  cat > "$WORK/cases.txt" <<'CASES'
s/\(.*\)/\U\1/
s/\(.*\)/\L\1/
s/\w\+/\u&/g
s/\w\+/\l&/g
s/.*/\U&\E/
s/\(b\?\)-/\u\1x/g
s/[a-z]*/\U&/g
s/.*/\u&&/
s/\(.\)\(.*\)/\U\1\L\2/
s/\(.*\)/\U\1\Etail/
CASES
  fails=0
  while IFS= read -r cmd; do
    [ -z "$cmd" ] && continue
    gnu_out="$(sed "$cmd" "$WORK/gnu-in.txt" 2>&1 || true)"
    our_out="$("$WORK/sed-patched" "$cmd" "$WORK/gnu-in.txt" 2>&1 || true)"
    if [ "$gnu_out" != "$our_out" ]; then
      fails=$((fails + 1))
      echo "MISMATCH: $cmd"
      echo "  gnu: $(printf '%s' "$gnu_out" | head -3 | tr '\n' '|')"
      echo "  sed: $(printf '%s' "$our_out" | head -3 | tr '\n' '|')"
    fi
  done < "$WORK/cases.txt"
  echo "gnu comparison: $fails mismatch(es)"
fi

echo
echo "=================== done ==================="
