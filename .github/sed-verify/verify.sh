#!/usr/bin/env bash
# Verification harness for uutils/sed PR #557 ("\U \L \u \l \E" case-conversion escapes).
#
# Builds several revisions of uutils/sed and compares instruction counts
# (valgrind/callgrind) on the `number_fix` workload from benches/sed_bench.rs,
# the benchmark CodSpeed reports as regressed, plus a case-conversion workload.
#
# Environment knobs:
#   SED_REPO     git url to clone           (default: dedsec-terminal/sed)
#   BASE_SHA     baseline revision          (default: upstream main at PR time)
#   PR_HEAD      PR head revision           (default: 626ce4f)
#   PATCHES      space separated patch files applied on top of PR_HEAD
#   EXTRA_SHAS   extra revisions to measure
#   SCALE        benchmark input lines      (default: 100000)
#   CHECK_TESTS  1 to run fmt/clippy/tests/GNU-diff on each patched tree
set -uo pipefail

SED_REPO="${SED_REPO:-https://github.com/dedsec-terminal/sed.git}"
BASE_SHA="${BASE_SHA:-c46dd6dab61a6a571bf08cb6b333e4fe1f3636c3}"
PR_HEAD="${PR_HEAD:-626ce4f02a3b100e1fddcc584adb4f1be50f9d78}"
PATCHES="${PATCHES:-${PATCH:-}}"
EXTRA_SHAS="${EXTRA_SHAS:-}"
SCALE="${SCALE:-100000}"
CHECK_TESTS="${CHECK_TESTS:-0}"

WORK="${WORK:-$HOME/sedwork}"
CARGO_TARGET_DIR="$WORK/target"
export CARGO_TARGET_DIR
mkdir -p "$WORK"
cd "$WORK"

step() { echo; echo "=== $* ==="; }

echo "=================== sed PR #557 verification harness ==================="
echo "base=$BASE_SHA"
echo "head=$PR_HEAD"
echo "patches='$PATCHES'"
echo "extra='$EXTRA_SHAS'"
echo "scale=$SCALE check_tests=$CHECK_TESTS"
rustc --version || true
cargo --version || true
valgrind --version || true
python3 --version || true

step "benchmark input"
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
echo "input: $(wc -l < "$DATA") lines, $(wc -c < "$DATA") bytes"

step "checkout"
REPO="$WORK/sed"
if [ ! -d "$REPO/.git" ]; then
  git clone --quiet "$SED_REPO" "$REPO" || { echo "CLONE FAILED"; exit 1; }
fi
git -C "$REPO" fetch --quiet --all --prune || true

NUM_FIX_SCRIPT='s/\([0-9]\)\.\([0-9]\)/\1\2/g;s/\([0-9]\),\([0-9]\)/\1.\2/g'
CASE_SCRIPT='s/\([0-9]\)\([0-9]*\)/\u\1\L\2/g'

build_variant() { # $1=label $2=sha $3=patch-or-empty
  local label="$1" sha="$2" patch="${3:-}"
  local wt="$WORK/wt-$label"
  rm -rf "$wt"
  git -C "$REPO" worktree prune
  if ! git -C "$REPO" worktree add --quiet --force --detach "$wt" "$sha"; then
    echo "BUILD FAILED ($label): cannot check out $sha"
    return 1
  fi
  if [ -n "$patch" ]; then
    if ! git -C "$wt" apply --verbose "$patch"; then
      echo "BUILD FAILED ($label): patch $patch does not apply"
      return 1
    fi
  fi
  echo "--- building $label ($(git -C "$REPO" rev-parse --short "$sha")${patch:+ + $(basename "$patch")}) ---"
  if ! ( cd "$wt" && cargo build --release --bin sed 2>&1 | tail -25 ); then
    echo "BUILD FAILED ($label)"
    return 1
  fi
  cp "$CARGO_TARGET_DIR/release/sed" "$WORK/sed-$label" || { echo "BUILD FAILED ($label): no binary"; return 1; }
  echo "built $WORK/sed-$label ($(stat -c%s "$WORK/sed-$label") bytes)"
}

measure() { # $1=label $2=script
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

REPO_ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
ABS_PATCHES=()
for p in $PATCHES; do
  case "$p" in
    /*) ABS_PATCHES+=("$p") ;;
    *) ABS_PATCHES+=("$REPO_ROOT/$p") ;;
  esac
done

step "builds"
LABELS=()
build_variant base "$BASE_SHA" && LABELS+=(base)
build_variant head "$PR_HEAD" && LABELS+=(head)
for p in "${ABS_PATCHES[@]:-}"; do
  [ -n "$p" ] || continue
  label="$(basename "$p" .patch)"
  build_variant "$label" "$PR_HEAD" "$p" && LABELS+=("$label")
done
for sha in $EXTRA_SHAS; do
  short="$(git -C "$REPO" rev-parse --short "$sha")"
  build_variant "extra-$short" "$sha" && LABELS+=("extra-$short")
done
if [ "${#LABELS[@]}" -eq 0 ]; then
  echo "NO VARIANT BUILT -- aborting"
  exit 1
fi

step "results"
rm -f "$WORK/results.txt"
printf "%-16s %18s %18s\n" variant "number_fix(Ir)" "case_conv(Ir)"
for label in "${LABELS[@]}"; do
  nf="$(measure "$label" "$NUM_FIX_SCRIPT")"
  cc="$(measure "$label" "$CASE_SCRIPT")"
  printf "%-16s %18s %18s\n" "$label" "$nf" "$cc"
  echo "$label $nf $cc" >> "$WORK/results.txt"
done

step "deltas vs base (negative = fewer instructions = faster)"
awk '{
    nf[$1]=$2; cc[$1]=$3; order[NR]=$1
  }
  END {
    bn=nf["base"]; bc=cc["base"]
    if (bn == 0 || bc == 0) { print "base measurement missing"; exit }
    for (i=1;i<=NR;i++) {
      l=order[i]; if (l in seen) continue; seen[l]=1
      printf "%-16s number_fix %+7.2f%%   case_conv %+7.2f%%\n", l,
         (nf[l]-bn)*100.0/bn, (cc[l]-bc)*100.0/bc
    }
  }' "$WORK/results.txt"

step "verdict"
awk '{
    nf[$1]=$2;
  }
  END {
    b=nf["base"]
    for (l in nf) if (l != "base")
      printf "%-16s %s (number_fix %+0.2f%% vs base)\n", l, (nf[l] <= b*1.002 ? "PARITY-OK" : "SLOWER-THAN-BASE"), (nf[l]-b)*100.0/b
  }' "$WORK/results.txt"

step "per-function instruction deltas (base vs head, top 20)"
python3 - "$WORK/annotate-base.txt" "$WORK/annotate-head.txt" <<'PY' || echo "annotation parse failed"
import re, sys

def parse(path):
    d = {}
    try:
        fh = open(path, errors="replace")
    except OSError:
        return d
    for line in fh:
        m = re.match(r"\s*([\d,]+)\s+\(\s*[\d.]+%\)\s+(.*)$", line)
        if m:
            d[m.group(2).strip()] = int(m.group(1).replace(",", ""))
    return d

a, b = parse(sys.argv[1]), parse(sys.argv[2])
rows = sorted(((b.get(k, 0) - a.get(k, 0), k) for k in set(a) | set(b)),
              key=lambda kv: -abs(kv[0]))[:20]
for delta, name in rows:
    print(f"{delta:>16}  {a.get(name, 0):>16} {b.get(name, 0):>16}  {name[:110]}")
PY

if [ "$CHECK_TESTS" = "1" ]; then
  for p in "${ABS_PATCHES[@]:-}"; do
    [ -n "$p" ] || continue
    wt="$WORK/wt-$(basename "$p" .patch)"
    [ -d "$wt" ] || continue
    step "checks on $(basename "$p")"
    if ( cd "$wt" && cargo fmt --all -- --check >/dev/null 2>&1 ); then
      echo "cargo fmt: OK"
    else
      echo "cargo fmt: NEEDS-FORMATTING, rustfmt would change:"
      ( cd "$wt" && cargo fmt --all && git --no-pager diff -U1 -- src/sed | head -80 )
    fi
    ( cd "$wt" && cargo clippy --all-targets --all-features -- -D warnings > "$WORK/clippy.log" 2>&1 \
        && echo "cargo clippy: OK" ) || { echo "cargo clippy: FAILED"; tail -25 "$WORK/clippy.log"; }
    ( cd "$wt" && cargo test > "$WORK/test.log" 2>&1 && echo "cargo test: OK" ) \
        || { echo "cargo test: FAILED"; grep -E "FAILED|panicked|^error|failures:" "$WORK/test.log" | head -25; }

    step "differential check against GNU sed ($(basename "$p"))"
    printf 'ABC DEF\nabC def\nhello world 123\nMIXed Case Here\n\xc3\xa9t\xc3\xa9 \xc3\x89T\xc3\x89\n' > "$WORK/gnu-in.txt"
    cat > "$WORK/cases.txt" <<'CASES'
s/\(.*\)/\U\1/
s/\(.*\)/\L\1/
s/\w\+/\u&/g
s/\w\+/\l&/g
s/.*/\U&\E/
s/[a-z]*/\U&/g
s/.*/\u&&/
s/\(.\)\(.*\)/\U\1\L\2/
s/\(.*\)/\U\1\Etail/
s/\([0-9]\)\([0-9]*\)/\u\1\L\2/g
CASES
    fails=0
    while IFS= read -r cmd; do
      [ -z "$cmd" ] && continue
      gnu_out="$(sed "$cmd" "$WORK/gnu-in.txt" 2>&1 || true)"
      our_out="$("$WORK/sed-$(basename "$p" .patch)" "$cmd" "$WORK/gnu-in.txt" 2>&1 || true)"
      if [ "$gnu_out" != "$our_out" ]; then
        fails=$((fails + 1))
        echo "MISMATCH: $cmd"
        echo "  gnu: $(printf '%s' "$gnu_out" | head -2 | tr '\n' '|')"
        echo "  sed: $(printf '%s' "$our_out" | head -2 | tr '\n' '|')"
      fi
    done < "$WORK/cases.txt"
    echo "gnu comparison: $fails mismatch(es)"
  done
fi

echo
echo "=================== done ==================="
