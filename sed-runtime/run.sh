#!/usr/bin/env bash
# Runtime (walltime) companion to .github/sed-verify/verify.sh.
#
# The instruction-count harness cannot explain a *walltime* style delta such as
# CodSpeed's "-2.46%". This script measures real time instead, on the same
# runner, in two ways:
#
#   1. end-to-end: each built `sed` binary on the `number_fix` workload
#      (the exact input benches/sed_bench.rs::number_fix builds);
#   2. a minimal no-regex C model of the same two sed scripts, which bounds how
#      much walltime the substitution loop itself can account for, and how much
#      a per-match temporary buffer (mode 1) adds on top of a direct write.
#
# Rounds are interleaved (one run per variant per round) so machine drift
# affects every variant equally; best/mean per variant are reported.
set -uo pipefail

SED_REPO="${SED_REPO:-https://github.com/dedsec-terminal/sed.git}"
BASE_SHA="${BASE_SHA:-c46dd6dab61a6a571bf08cb6b333e4fe1f3636c3}"
PR_HEAD="${PR_HEAD:-626ce4f02a3b100e1fddcc584adb4f1be50f9d78}"

WORK="${WORK:-$HOME/runtime}"
REPO_ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
REQUEST="${REQUEST:-$REPO_ROOT/sed-runtime/request.txt}"
ROUNDS="${ROUNDS:-7}"
SCALE="${SCALE:-100000}"
EXTRA_SHAS="${EXTRA_SHAS:-}"
PATCHES="${PATCHES:-}"
if [ -f "$REQUEST" ]; then
  # shellcheck disable=SC1090
  . "$REQUEST"
  # accept lower case keys as well (same spelling as the sed-verify request file)
  [ -n "${patches:-}" ] && PATCHES="${PATCHES:-$patches}"
  [ -n "${extra_shas:-}" ] && EXTRA_SHAS="${EXTRA_SHAS:-$extra_shas}"
  [ -n "${rounds:-}" ] && ROUNDS="${ROUNDS:-$rounds}"
  [ -n "${scale:-}" ] && SCALE="${SCALE:-$scale}"
fi
export CARGO_TARGET_DIR="$WORK/target"
mkdir -p "$WORK"
cd "$WORK"
REPORT="$WORK/report.txt"
: > "$REPORT"
exec > >(tee -a "$REPORT") 2>&1

step() { echo; echo "=== $* ==="; }

step "environment"
date -u
uname -a
grep -m1 "model name" /proc/cpuinfo || true
nproc || true
cat /sys/fs/cgroup/cpu.max 2>/dev/null || true
echo "rounds=$ROUNDS scale=$SCALE base=$BASE_SHA head=$PR_HEAD patches='$PATCHES' extra='$EXTRA_SHAS'"
rustc --version || true
cargo --version || true
cc --version | head -1 || true
sed --version | head -1 || true

NUM_FIX_SCRIPT='s/\([0-9]\)\.\([0-9]\)/\1\2/g;s/\([0-9]\),\([0-9]\)/\1.\2/g'

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
GNU_SHA="$(sed "$NUM_FIX_SCRIPT" "$DATA" | sha256sum | cut -c1-16)"
echo "GNU sed output sha256=$GNU_SHA"

step "checkout + builds"
REPO="$WORK/sed"
if [ ! -d "$REPO/.git" ]; then
  git clone --quiet "$SED_REPO" "$REPO" || { echo "CLONE FAILED"; exit 1; }
fi
git -C "$REPO" fetch --quiet --all --prune || true

build_variant() { # $1=label $2=sha $3=patch-or-empty
  local label="$1"
  local sha="$2"
  local patch="${3:-}"
  local wt="$WORK/wt-$label"
  rm -rf "$wt"
  git -C "$REPO" worktree prune
  if ! git -C "$REPO" worktree add --quiet --force --detach "$wt" "$sha"; then
    echo "BUILD FAILED ($label): cannot check out $sha"
    return 1
  fi
  if [ -n "$patch" ]; then
    if ! git -C "$wt" apply "$patch"; then
      echo "BUILD FAILED ($label): patch $patch does not apply"
      return 1
    fi
  fi
  if ! ( cd "$wt" && cargo build --release --bin sed 2>&1 | tail -15 ); then
    echo "BUILD FAILED ($label)"
    return 1
  fi
  cp "$CARGO_TARGET_DIR/release/sed" "$WORK/sed-$label" || return 1
  echo "built sed-$label ($(stat -c%s "$WORK/sed-$label") bytes)"
}

LABELS=()
build_variant base "$BASE_SHA" && LABELS+=(base)
build_variant head "$PR_HEAD" && LABELS+=(head)
for p in $PATCHES; do
  case "$p" in
    /*) abs="$p" ;;
    *) abs="$REPO_ROOT/$p" ;;
  esac
  label="$(basename "$abs" .patch)"
  build_variant "$label" "$PR_HEAD" "$abs" && LABELS+=("$label")
done
for sha in $EXTRA_SHAS; do
  short="$(git -C "$REPO" rev-parse --short "$sha")"
  build_variant "extra-$short" "$sha" && LABELS+=("extra-$short")
done
if [ "${#LABELS[@]}" -eq 0 ]; then
  echo "NO VARIANT BUILT"
  exit 1
fi

step "GNU sed reference walltime"
for round in 1 2 3; do
  start=$(date +%s%N)
  sed "$NUM_FIX_SCRIPT" "$DATA" > /dev/null
  end=$(date +%s%N)
  echo "gnu-sed round$round $(( (end - start) / 1000000 ))ms"
done

step "no-regex model of the same substitution loop"
cat > "$WORK/model.c" <<'CSRC'
/* Minimal model of the `number_fix` substitution (benches/sed_bench.rs):
 * left-to-right scans, no regex engine, output accumulated into one buffer.
 *
 *   s/\([0-9]\)\.\([0-9]\)/\1\2/g     digits around '.' are joined
 *   s/\([0-9]\),\([0-9]\)/\1.\2/g     digits around ',' keep a '.'
 *
 * mode 0 writes matches straight into the output buffer; mode 1 builds every
 * replacement in its own heap block, copies it into the output and frees it -
 * i.e. what a per-match temporary buffer costs
 * (`let mut result = Vec::new(); ..; target.extend_from_slice(&result)`).
 *
 * usage: model input.txt [rounds] [--write]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static int is_digit(unsigned char c) { return c >= '0' && c <= '9'; }

static size_t one_pass(const unsigned char *src, size_t n, unsigned char sep,
                       unsigned char repl, int keep_sep, unsigned char *out,
                       int mode) {
    size_t i = 0, o = 0;
    while (i < n) {
        unsigned char b = src[i];
        if (i + 2 < n && is_digit(b) && src[i + 1] == sep && is_digit(src[i + 2])) {
            if (mode == 0) {
                out[o++] = b;
                if (keep_sep) out[o++] = repl;
                out[o++] = src[i + 2];
            } else {
                size_t len = keep_sep ? 3 : 2;
                unsigned char *tmp = malloc(len);
                tmp[0] = b;
                if (keep_sep) tmp[1] = repl;
                tmp[len - 1] = src[i + 2];
                memcpy(out + o, tmp, len);
                o += len;
                free(tmp);
            }
            i += 3;
        } else {
            out[o++] = b;
            i += 1;
        }
    }
    return o;
}

static size_t run_once(const unsigned char *src, size_t size, unsigned char *mid,
                       unsigned char *dst, int mode) {
    size_t n1 = one_pass(src, size, '.', 0, 0, mid, mode);
    return one_pass(mid, n1, ',', '.', 1, dst, mode);
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s input [rounds] [--write]\n", argv[0]); return 2; }
    const char *path = argv[1];
    int rounds = argc > 2 ? atoi(argv[2]) : 5;
    if (rounds < 1) rounds = 1;
    int write_out = argc > 3 && strcmp(argv[3], "--write") == 0;

    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *src = malloc((size_t)size + 1);
    if (!src || fread(src, 1, (size_t)size, f) != (size_t)size) return 1;
    fclose(f);
    unsigned char *mid = malloc((size_t)size + 1);
    unsigned char *dst = malloc((size_t)size + 1);
    if (!mid || !dst) return 1;

    size_t n2 = run_once(src, (size_t)size, mid, dst, 0);
    if (write_out) { fwrite(dst, 1, n2, stdout); return 0; }

    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n2; i++) { h ^= dst[i]; h *= 1099511628211ULL; }

    for (int mode = 0; mode < 2; mode++) {
        double best = 1e9, total = 0.0;
        for (int r = 0; r < rounds; r++) {
            double t0 = now_sec();
            size_t got = run_once(src, (size_t)size, mid, dst, mode);
            double dt = now_sec() - t0;
            if (dt < best) best = dt;
            total += dt;
            if (got == 0) fprintf(stderr, "empty output\n");
        }
        printf("model %-11s best=%8.4fms mean=%8.4fms bytes=%zu hash=%016llx\n",
               mode ? "--alloc" : "direct", best * 1000.0, total * 1000.0 / rounds,
               n2, (unsigned long long)h);
    }
    return 0;
}
CSRC
if cc -O2 -o "$WORK/model" "$WORK/model.c"; then
  "$WORK/model" "$DATA" 1 --write > "$WORK/model-out.txt"
  MODEL_SHA="$(sha256sum "$WORK/model-out.txt" | cut -c1-16)"
  echo "model output sha256=$MODEL_SHA (matches GNU sed: $([ "$MODEL_SHA" = "$GNU_SHA" ] && echo yes || echo NO))"
  "$WORK/model" "$DATA" 7
else
  echo "model build failed (ignored)"
fi

step "end-to-end timing (interleaved rounds: one run per variant per round)"
rm -f "$WORK/times.txt"
for round in $(seq 1 "$ROUNDS"); do
  for label in "${LABELS[@]}"; do
    start=$(date +%s%N)
    "$WORK/sed-$label" "$NUM_FIX_SCRIPT" "$DATA" > "$WORK/rt-$label.bin" 2> "$WORK/rt-$label.err"
    rc=$?
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    sha="$(sha256sum "$WORK/rt-$label.bin" | cut -c1-16)"
    ok="ok"
    [ "$rc" = "0" ] || ok="EXIT-$rc"
    [ "$sha" = "$GNU_SHA" ] || ok="$ok OUTPUT!=GNU"
    echo "$label $ms $round $ok" >> "$WORK/times.txt"
  done
done

step "per variant (best / mean / all runs)"
awk '{ n[$1]++; s[$1]+=$2; if (!($1 in mn) || $2<mn[$1]) mn[$1]=$2; vals[$1]=vals[$1]" "$2; if ($4!="ok") bad[$1]=1 }
  END { for (l in n) printf "%-16s best=%7dms mean=%8.1fms runs=%d%s [%s ]\n", l, mn[l], s[l]/n[l], n[l], (l in bad ? "  <-- CHECK OUTPUT" : ""), vals[l] }' \
  "$WORK/times.txt" | sort

step "SUMMARY"
echo "runner cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs) cores=$(nproc)"
echo "GNU sed output sha=$GNU_SHA model sha=${MODEL_SHA:-n/a}"
awk '{ n[$1]++; s[$1]+=$2; if (!($1 in mn) || $2<mn[$1]) mn[$1]=$2 }
  END { for (l in n) printf "%-16s best=%7dms mean=%8.1fms\n", l, mn[l], s[l]/n[l] }' \
  "$WORK/times.txt" | sort
echo "codSpeed claim to explain: number_fix 1.2s -> 1.2s, -2.46% (i.e. ~29ms more on a 1.2s benchmark)"
echo "done"
