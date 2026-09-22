#!/usr/bin/env bash
# Verification harness for uutils/sed PR #557 ("\U \L \u \l \E" case-conversion escapes).
#
# Builds several revisions of uutils/sed and compares instruction counts
# (valgrind/callgrind) on the `number_fix` workload from benches/sed_bench.rs,
# the benchmark CodSpeed reports as regressed, plus a case-conversion workload.
# Every measured run is also checked for exit status and byte-identical output
# against the system GNU sed, so a broken variant can never look "faster".
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
sed --version | head -1 || true

step "benchmark input"
DATA="$WORK/number_fix.txt"
if [ ! -f "$DATA" ] || [ "$(wc -l < "$DATA")" != "$SCALE" ]; then
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

step "GNU sed reference output"
GNUC="$(command -v sed || true)"
gnu_ref() { # $1=script $2=tag -> "rc sha"
  local script="$1" tag="$2" out="$WORK/gnu-$tag.bin" rc sha
  if [ -z "$GNUC" ]; then echo "n/a n/a"; return; fi
  "$GNUC" "$script" "$DATA" > "$out" 2>/dev/null
  rc=$?
  sha="$(sha256sum "$out" | cut -c1-16)"
  echo "$rc $sha"
}
read -r GNU_NF_RC GNU_NF_SHA < <(gnu_ref "$NUM_FIX_SCRIPT" nf)
read -r GNU_CC_RC GNU_CC_SHA < <(gnu_ref "$CASE_SCRIPT" cc)
echo "GNU sed number_fix: rc=$GNU_NF_RC sha256=$GNU_NF_SHA"
echo "GNU sed case_conv : rc=$GNU_CC_RC sha256=$GNU_CC_SHA"

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
  # commit so that "cargo fmt" diffs below show only rustfmt's own changes
  git -C "$wt" add -A
  git -C "$wt" -c user.name=verify -c user.email=verify@example.com \
    commit --quiet -m "verify: ${label}" || true
  echo "--- building $label ($(git -C "$REPO" rev-parse --short "$sha")${patch:+ + $(basename "$patch")}) ---"
  if ! ( cd "$wt" && cargo build --release --bin sed 2>&1 | tail -25 ); then
    echo "BUILD FAILED ($label)"
    return 1
  fi
  cp "$CARGO_TARGET_DIR/release/sed" "$WORK/sed-$label" || { echo "BUILD FAILED ($label): no binary"; return 1; }
  echo "built $WORK/sed-$label ($(stat -c%s "$WORK/sed-$label") bytes)"
}

measure() { # $1=label $2=script $3=tag -> "ir rc sha"
  local label="$1" script="$2" tag="$3"
  local log="$WORK/cg-$label-$tag.log" out="$WORK/out-$label-$tag.bin" rc ir sha
  rm -f "$out"
  valgrind --tool=callgrind --callgrind-out-file="$WORK/cg-$label-$tag.out" \
    --log-file="$log" "$WORK/sed-$label" "$script" "$DATA" \
    > "$out" 2> "$WORK/err-$label-$tag.txt"
  rc=$?
  callgrind_annotate --threshold=100 --auto=no "$WORK/cg-$label-$tag.out" \
    > "$WORK/annotate-$label-$tag.txt" 2>/dev/null || true
  ir="$(python3 - "$log" <<'PY'
import re, sys
txt = open(sys.argv[1], errors="replace").read()
m = re.search(r"I\s+refs:\s+([\d,]+)", txt)
print(m.group(1).replace(",", "") if m else "0")
PY
)"
  sha="$(sha256sum "$out" 2>/dev/null | cut -c1-16)"
  echo "$ir $rc $sha"
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
printf "%-22s %18s %18s  %s\n" variant "number_fix(Ir)" "case_conv(Ir)" "output check"
for label in "${LABELS[@]}"; do
  read -r nf nf_rc nf_sha < <(measure "$label" "$NUM_FIX_SCRIPT" nf)
  read -r cc cc_rc cc_sha < <(measure "$label" "$CASE_SCRIPT" cc)
  note="ok"
  [ "$nf_rc" = "$GNU_NF_RC" ] || note="number_fix exit $nf_rc"
  [ "$cc_rc" = "$GNU_CC_RC" ] || note="$note; case_conv exit $cc_rc"
  [ "$nf_sha" = "$GNU_NF_SHA" ] || note="$note; number_fix OUTPUT!=GNU"
  [ "$cc_sha" = "$GNU_CC_SHA" ] || note="$note; case_conv OUTPUT!=GNU"
  printf "%-22s %18s %18s  %s\n" "$label" "$nf" "$cc" "$note"
  echo "$label $nf $cc $note" >> "$WORK/results.txt"
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
      printf "%-22s number_fix %+7.2f%%   case_conv %+7.2f%%\n", l,
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
      printf "%-22s %s (number_fix %+0.2f%% vs base)\n", l, (nf[l] <= b*1.002 ? "PARITY-OK" : "SLOWER-THAN-BASE"), (nf[l]-b)*100.0/b
  }' "$WORK/results.txt"

step "per-function instruction deltas (base vs head, top 12)"
python3 - "$WORK/annotate-base-nf.txt" "$WORK/annotate-head-nf.txt" <<'PY' || echo "annotation parse failed"
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
            name = m.group(2).strip().replace("[/home/runner/sedwork/sed-base]", "")
            name = name.replace("[/home/runner/sedwork/sed-head]", "")
            d[name] = int(m.group(1).replace(",", ""))
    return d


a, b = parse(sys.argv[1]), parse(sys.argv[2])
rows = sorted(((b.get(k, 0) - a.get(k, 0), k) for k in set(a) | set(b)),
              key=lambda kv: -abs(kv[0]))[:12]
for delta, name in rows:
    print(f"{delta:>16}  {a.get(name, 0):>16} {b.get(name, 0):>16}  {name[:80]}")
PY

rm -f "$WORK/checks.txt"
if [ "$CHECK_TESTS" = "1" ]; then
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
  for p in "${ABS_PATCHES[@]:-}"; do
    [ -n "$p" ] || continue
    name="$(basename "$p" .patch)"
    wt="$WORK/wt-$name"
    [ -d "$wt" ] || continue
    step "checks on $name"
    verdict_fmt="OK"
    if ! ( cd "$wt" && cargo fmt --all -- --check >/dev/null 2>&1 ); then
      verdict_fmt="FAIL"
      echo "cargo fmt: FAILED, rustfmt wants (patch is already committed, so this is rustfmt only):"
      ( cd "$wt" && cargo fmt --all && git --no-pager diff -U1 | head -60 )
    else
      echo "cargo fmt: OK"
    fi
    verdict_clippy="OK"
    if ! ( cd "$wt" && cargo clippy --all-targets --all-features -- -D warnings > "$WORK/clippy-$name.log" 2>&1 ); then
      verdict_clippy="FAIL"
      echo "cargo clippy: FAILED"
      tail -25 "$WORK/clippy-$name.log"
    else
      echo "cargo clippy: OK"
    fi
    verdict_test="OK"
    if ! ( cd "$wt" && cargo test > "$WORK/test-$name.log" 2>&1 ); then
      verdict_test="FAIL"
      echo "cargo test: FAILED"
      grep -E "FAILED|panicked|^error|failures:" "$WORK/test-$name.log" | head -25
    else
      echo "cargo test: OK"
    fi

    fails=0
    while IFS= read -r cmd; do
      [ -z "$cmd" ] && continue
      gnu_out="$(sed "$cmd" "$WORK/gnu-in.txt" 2>&1 || true)"
      our_out="$("$WORK/sed-$name" "$cmd" "$WORK/gnu-in.txt" 2>&1 || true)"
      if [ "$gnu_out" != "$our_out" ]; then
        fails=$((fails + 1))
        echo "MISMATCH: $cmd"
        echo "  gnu: $(printf '%s' "$gnu_out" | head -2 | tr '\n' '|')"
        echo "  sed: $(printf '%s' "$our_out" | head -2 | tr '\n' '|')"
      fi
    done < "$WORK/cases.txt"
    echo "gnu comparison: $fails mismatch(es)"
    echo "$name fmt=$verdict_fmt clippy=$verdict_clippy test=$verdict_test gnu-diff=$fails-mismatch" >> "$WORK/checks.txt"
  done
fi

# Keep this last: the report channel only keeps the tail of the output.
step "SUMMARY"
echo "base=$BASE_SHA head=$PR_HEAD scale=$SCALE"
echo "GNU reference: number_fix rc=$GNU_NF_RC sha=$GNU_NF_SHA | case_conv rc=$GNU_CC_RC sha=$GNU_CC_SHA"
echo "variant                number_fix(Ir)   case_conv(Ir)   output-check"
awk '{ printf "%-22s %18s %18s  %s\n", $1, $2, $3, substr($0, index($0,$4)) }' "$WORK/results.txt" 2>/dev/null
awk '{
    nf[$1]=$2; cc[$1]=$3; order[NR]=$1
  }
  END {
    bn=nf["base"]; bc=cc["base"]
    if (bn == 0) { print "base measurement missing"; exit }
    for (i=1;i<=NR;i++) {
      l=order[i]; if (l in seen) continue; seen[l]=1
      printf "%-22s %+6.2f%% / %+6.2f%%   %s\n", l,
         (nf[l]-bn)*100.0/bn, (cc[l]-bc)*100.0/bc,
         (nf[l] <= bn*1.002 ? "PARITY-OK" : "SLOWER-THAN-BASE")
    }
  }' "$WORK/results.txt"
[ -f "$WORK/checks.txt" ] && cat "$WORK/checks.txt"

echo
echo "=================== done ==================="
