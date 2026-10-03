#!/bin/bash
# End-to-end full secret-key recovery against Polar-LAC via the PHYSICAL oracle:
# a REAL decapsulation wall-clock timer (decaps = a + b*J). Parallel across
# cores; live per-unit progress + ETA stream on stderr.
#
# Timing is frequency-sensitive: pin the CPU (turbo off / performance governor)
# before running for stable measurements.
#
# Usage:
#   bash run_timing.sh            # ref_light
#
# Env:
#   NT   worker threads (default 6)
set -e

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

NT=${NT:-6}
PARAMS="POLARLAC-Light : q=257 n=256 K=2 c2=3-bit (D_C2_BITS=3) T=576"
UNITS="256 blocks (= 512 secret coefficients)"

bin="$ROOT/build/timing_fullkey_light"
if [ ! -x "$bin" ]; then
    echo ">>> building ..."
    bash "$ROOT/build.sh"
    echo
fi

echo ">>> TIMING full-key recovery  [$PARAMS]  --  $UNITS, $NT threads"
echo "    (physical oracle = real decaps clock; measured ~66 min on 6 cores)"
echo "    (freq-sensitive: pin CPU for stable timing; progress + ETA stream below)"
"$bin" "$NT"
