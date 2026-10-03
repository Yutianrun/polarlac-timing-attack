#!/bin/bash
# Full secret-key recovery against Polar-LAC via the THEORETICAL oracle:
# the exact FO rejection-sampling round count J (a plaintext-checking oracle).
# Fast, deterministic, no timing. Live progress streams on stderr.
#
# Usage:
#   bash run_pco.sh            # ref_light
set -e

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

PARAMS="POLARLAC-Light : q=257 n=256 K=2 c2=3-bit (D_C2_BITS=3) T=576"
UNITS="256 blocks (= 512 secret coefficients)"

bin="$ROOT/build/pco_keyrecovery_light"
if [ ! -x "$bin" ]; then
    echo ">>> building ..."
    bash "$ROOT/build.sh"
    echo
fi

echo ">>> PCO full-key recovery  [$PARAMS]  --  $UNITS"
echo "    (theoretical oracle = exact FO round-count J; progress + ETA stream below)"
"$bin"
