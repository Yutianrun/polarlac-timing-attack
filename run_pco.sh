#!/bin/bash
# Full secret-key recovery against Polar-LAC via the THEORETICAL oracle:
# the exact FO rejection-sampling round count J (a plaintext-checking oracle).
# Fast, deterministic, no timing. Live progress streams on stderr.
#
# Usage:
#   bash run_pco.sh            # ref_light (default)
#   bash run_pco.sh 128        # ref128
set -e

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

ref=${1:-light}       # light | 128
case "$ref" in
    light) PARAMS="POLARLAC-Light : q=257 n=256 K=2 c2=3-bit (D_C2_BITS=3) T=576" ;;
    128)   PARAMS="POLARLAC kem-30: q=257 n=256 K=2 c2=4-bit (D_C2_BITS=4) T=900" ;;
    *)     echo "usage: bash run_pco.sh [light|128]"; exit 2 ;;
esac
UNITS="256 blocks (= 512 secret coefficients)"

bin="$ROOT/build/pco_keyrecovery_$ref"
if [ ! -x "$bin" ]; then
    echo ">>> building ($ref) ..."
    bash "$ROOT/build.sh" "$ref"
    echo
fi

echo ">>> PCO full-key recovery  [$PARAMS]  --  $UNITS"
echo "    (theoretical oracle = exact FO round-count J; progress + ETA stream below)"
"$bin"
