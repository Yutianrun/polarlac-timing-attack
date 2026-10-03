#!/bin/bash
# Build the Polar-LAC chosen-ciphertext attacks against the bundled NGCC
# reference implementations.
#
# Two targets are vendored, self-contained (no external deps, clang/gcc only):
#   ref_light/  POLARLAC-Light  (q=257, K=2, c2 3-bit)   -- default
#   ref128/     POLARLAC kem-30 (q=257, K=2, c2 4-bit)
#
# Two attacks are kept, one of each kind:
#   pco_keyrecovery   full-key recovery via the block-isolation PCO
#                     (algorithmic / theoretical oracle; both refs)
#   timing_fullkey    end-to-end full-key recovery by REAL wall-clock timing,
#                     parallel across cores (physical oracle; both refs)
#
# Usage:
#   bash build.sh            # build both attacks for every target
#   bash build.sh light      # ref_light targets only
#   bash build.sh 128        # ref128 targets only
set -e

ROOT=$(cd "$(dirname "$0")" && pwd)
OUT="$ROOT/build"
CC=${CC:-/usr/bin/cc}
command -v "$CC" >/dev/null 2>&1 || CC=cc

# Reference backend switches (defaults match the NGCC submission: SM3, no conj-NTT).
DEFS="-DBIT_USE_SHAKE=0 -DRL_KEM_USE_CONJ_NTT_REJECTION=0"
CFLAGS="-std=gnu99 -O2 $DEFS"

# Common sources shared by every reference backend.
COMMON="auxfunc drng fips202 symmetric sample poly pke polar ntt fft KEM_AlgorithmInstance"

build() {      # $1 = attack .c   $2 = ref dir   $3 = output name
    local attack=$1 ref=$2 out=$3 objs=""
    local s
    for s in $COMMON; do objs="$objs $ROOT/$ref/$s.c"; done
    echo "== $out  ($attack vs $ref)"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS -I"$ROOT/$ref" "$ROOT/$attack" $objs -lm -lpthread -o "$OUT/$out"
}

mkdir -p "$OUT"

sel=${1:-all}

if [ "$sel" = "all" ] || [ "$sel" = "light" ]; then
    build pco_keyrecovery.c ref_light pco_keyrecovery_light
    build timing_fullkey.c  ref_light timing_fullkey_light
fi

if [ "$sel" = "all" ] || [ "$sel" = "128" ]; then
    build pco_keyrecovery.c ref128 pco_keyrecovery_128
    build timing_fullkey.c  ref128 timing_fullkey_128
fi

echo
echo "done -> $OUT"
ls -1 "$OUT"
