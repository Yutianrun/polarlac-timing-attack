# Polar-LAC timing attack

Chosen-ciphertext key-recovery against the bundled Polar-LAC reference KEMs.

```bash
bash build.sh       # build everything
bash run_pco.sh     # theoretical oracle (fast, deterministic)
bash run_timing.sh  # physical oracle (real decaps wall-clock)
```

## Setup

Timing results were measured **in parallel on an i7-9700 with Turbo disabled**
(fixed clock, `performance` governor). Pin the CPU the same way before timing or
the thresholds won't hold.

## Fix before you run

Some values are **hardcoded to that machine** — tune them for yours:

- **Core binding**: workers are not pinned. Set affinity (`taskset` /
  `sched_setaffinity`) to idle physical cores and keep threads ≤ core count.
- **Thread count**: `NT=6` default in `run_timing.sh`.
- **Calibration**: warm-up/sample counts and screen/vote thresholds in
  `timing_fullkey.c` (`decaps_ns` warm-up loop, `cal[7]`, `SCRN`, `0.8`)
  are tuned to the 9700's clock — re-tune for your frequency.
