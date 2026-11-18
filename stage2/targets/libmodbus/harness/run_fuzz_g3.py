"""Fuzzing baseline (issue G3): >=5 trials/arm, equal iteration budget,
time-to-crash distributions. Arms: naive seeds vs AI-drafted seeds.

Each trial runs modbus_fuzz.py inside the ASan target-0367 container. Writes a
summary to results/fuzz-g3/summary.json.

    stage2/.venv/Scripts/python.exe targets/libmodbus/harness/run_fuzz_g3.py
"""
from __future__ import annotations
import json, subprocess, statistics
from pathlib import Path

LIBM = Path(__file__).resolve().parents[1]
# compose mounts targets/libmodbus/results -> /workspace/results
G3 = LIBM / "results" / "fuzz-g3"
ITERS = 1500
TRIALS = 5
ARMS = {"naive": "seeds-naive", "ai": "seeds-ai"}


def one_trial(arm_seed_dir: str, out_rel: str, rng: int) -> dict:
    cmd = ["docker", "compose", "--profile", "fuzz", "run", "--rm",
           "--entrypoint", "python3", "target-0367", "/opt/lab/modbus_fuzz.py",
           "--seeds", f"/workspace/results/fuzz-g3/{arm_seed_dir}",
           "--iterations", str(ITERS),
           "--output-dir", f"/workspace/results/fuzz-g3/{out_rel}",
           "--rng-seed", str(rng)]
    try:
        subprocess.run(cmd, cwd=LIBM, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"crash_found": False, "note": "timeout"}
    rj = G3 / out_rel / "fuzz_result.json"
    return json.loads(rj.read_text()) if rj.exists() else {"crash_found": False, "note": "no result"}


def main() -> int:
    summary = {}
    for arm, seed_dir in ARMS.items():
        trials = []
        for n in range(1, TRIALS + 1):
            r = one_trial(seed_dir, f"{arm}/trial{n}", n)
            crashed = r.get("crash_found", False)
            it = r.get("crash_iteration") if crashed else None
            el = r.get("elapsed_s")
            trials.append({"rng": n, "crash": crashed, "iters_to_crash": it, "elapsed_s": el})
            print(f"  {arm:6} trial{n}: crash={crashed} iters={it} time={el}s", flush=True)
        hits = [t for t in trials if t["crash"]]
        iters = [t["iters_to_crash"] for t in hits if t["iters_to_crash"] is not None]
        times = [t["elapsed_s"] for t in hits if t["elapsed_s"] is not None]
        summary[arm] = {
            "trials": trials,
            "crash_rate": f"{len(hits)}/{TRIALS}",
            "median_iters_to_crash": statistics.median(iters) if iters else None,
            "median_time_s": round(statistics.median(times), 1) if times else None,
        }
        print(f"{arm}: {len(hits)}/{TRIALS} crashed; "
              f"median iters={summary[arm]['median_iters_to_crash']} "
              f"time={summary[arm]['median_time_s']}s")
    (G3 / "summary.json").write_text(json.dumps(summary, indent=1))
    print("\nwrote results/fuzz-g3/summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
