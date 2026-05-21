#!/usr/bin/env python3
"""
Scores a candidate patched C file against the held-out corpus.

Usage: python3 score.py <path-to-candidate.c>

Builds the candidate with `clang -fsanitize=address,undefined` (falls back to gcc),
then runs every held-out input through the resulting binary.

Reward = 0.6 * exploit_suppression_rate + 0.4 * benign_correctness_rate
(performance is dropped from the tiny pilot since the parser is too small to
benchmark meaningfully).

Hard-fail (reward=0) if: build fails, or benign_correctness_rate < 0.75.

Prints a one-line summary + writes <candidate>.score.json next to the source.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS_HELD_OUT = os.path.join(ROOT, "corpus", "held_out")
CORPUS_DEV = os.path.join(ROOT, "corpus", "dev")


def pick_compiler() -> str:
    for cc in ("clang", "gcc"):
        if shutil.which(cc):
            return cc
    print("ERROR: neither clang nor gcc found in PATH")
    sys.exit(2)


def build(src: str, out: str, cc: str) -> tuple[bool, str]:
    cmd = [cc, "-O0", "-g", "-fsanitize=address,undefined", "-o", out, src]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode == 0, (p.stderr or p.stdout)


def run(binary: str, input_file: str, timeout_sec: float = 5.0) -> tuple[int, str, str]:
    """Returns (return_code, stdout, stderr). A non-zero return code from ASan
    looks like 1 with sanitizer text on stderr — that's the 'exploit triggered'
    signal."""
    try:
        env = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0", "PATH": os.environ.get("PATH", "")}
        p = subprocess.run([binary, input_file], capture_output=True, text=True,
                           timeout=timeout_sec, env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"


def is_sanitizer_report(stderr: str) -> bool:
    markers = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:",
               "SUMMARY: AddressSanitizer", "SUMMARY: UndefinedBehaviorSanitizer",
               "heap-buffer-overflow", "stack-buffer-overflow")
    return any(m in stderr for m in markers)


def collect(corpus_dir: str, prefix: str) -> list[str]:
    if not os.path.isdir(corpus_dir):
        return []
    return sorted(os.path.join(corpus_dir, f)
                  for f in os.listdir(corpus_dir)
                  if f.startswith(prefix) and f.endswith(".bin"))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: score.py <candidate.c>")
        return 2

    candidate = sys.argv[1]
    if not os.path.isfile(candidate):
        print(f"ERROR: {candidate} not found")
        return 2

    if not os.path.isdir(CORPUS_HELD_OUT):
        print(f"ERROR: corpus/held_out/ not found — run `python3 corpus.py` first")
        return 2

    cc = pick_compiler()
    print(f"compiler: {cc}")

    with tempfile.TemporaryDirectory() as tmp:
        # Build baseline (the original vulnerable.c — for expected benign output)
        baseline_src = os.path.join(ROOT, "vulnerable.c")
        baseline_bin = os.path.join(tmp, "baseline")
        ok, log = build(baseline_src, baseline_bin, cc)
        if not ok:
            print(f"FATAL: baseline build failed:\n{log[:400]}")
            return 2

        # Build candidate
        candidate_bin = os.path.join(tmp, "candidate")
        ok, log = build(candidate, candidate_bin, cc)
        if not ok:
            print(f"\n=== HARD FAIL: candidate build failed ===\n{log[:800]}")
            _emit(candidate, 0.0, {"build_ok": False, "build_log": log[:1000]})
            return 0

        # --- Benign correctness ---
        benign = collect(CORPUS_HELD_OUT, "valid_")
        benign_results = []
        for inp in benign:
            rc_b, out_b, _ = run(baseline_bin, inp)
            rc_c, out_c, err_c = run(candidate_bin, inp)
            asan = is_sanitizer_report(err_c)
            match = (rc_b == rc_c and out_b == out_c and not asan)
            benign_results.append({"input": os.path.basename(inp),
                                   "baseline_rc": rc_b, "candidate_rc": rc_c,
                                   "match": match, "asan": asan})
        benign_correct = sum(1 for r in benign_results if r["match"])
        benign_rate = benign_correct / max(len(benign_results), 1)

        # --- Exploit suppression ---
        exploits = collect(CORPUS_HELD_OUT, "exploit_")
        exploit_results = []
        for inp in exploits:
            rc_c, _, err_c = run(candidate_bin, inp)
            # Suppressed = no sanitizer report. Parser may exit non-zero (rejection)
            # or zero (cleanly handled) — both are fine, as long as no UB occurs.
            suppressed = not is_sanitizer_report(err_c)
            exploit_results.append({"input": os.path.basename(inp),
                                    "candidate_rc": rc_c,
                                    "suppressed": suppressed,
                                    "asan_excerpt": err_c[:200] if err_c else ""})
        exploits_suppressed = sum(1 for r in exploit_results if r["suppressed"])
        exploit_rate = exploits_suppressed / max(len(exploit_results), 1)

        # --- Reward ---
        hard_fail = []
        if benign_rate < 0.75:
            hard_fail.append(f"benign_correctness {benign_rate:.2f} < 0.75")

        if hard_fail:
            reward = 0.0
        else:
            reward = 0.6 * exploit_rate + 0.4 * benign_rate

        summary = {
            "candidate": candidate,
            "compiler": cc,
            "build_ok": True,
            "benign": {"correct": benign_correct, "total": len(benign_results),
                       "rate": round(benign_rate, 4), "details": benign_results},
            "exploits": {"suppressed": exploits_suppressed, "total": len(exploit_results),
                         "rate": round(exploit_rate, 4), "details": exploit_results},
            "reward": round(reward, 4),
            "hard_fail": hard_fail,
        }
        _emit(candidate, reward, summary)

        print(f"\n=== {candidate} ===")
        print(f"  benign correct:    {benign_correct}/{len(benign_results)}  ({benign_rate:.2f})")
        print(f"  exploits suppressed: {exploits_suppressed}/{len(exploit_results)}  ({exploit_rate:.2f})")
        if hard_fail:
            print(f"  HARD FAIL: {hard_fail}")
        print(f"  REWARD: {reward:.4f}")
        return 0


def _emit(candidate: str, reward: float, payload: dict) -> None:
    payload["reward"] = round(reward, 4)
    out = os.path.splitext(candidate)[0] + ".score.json"
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
