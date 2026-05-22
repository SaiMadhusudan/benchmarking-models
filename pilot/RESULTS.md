# Pilot Results

**Repo:** https://github.com/SaiMadhusudan/benchmarking-models

## Setup

- Target: [vulnerable.c](vulnerable.c) — 80-line TLV parser, 3 deliberate bugs across 2 classes.
- Held-out corpus: 4 benign + 5 exploits (1 instance-match with dev exploit, 4 class-variants).
- Scoring: `reward = 0.6 × exploit_suppression + 0.4 × benign_correctness`.
- Compiler: `clang -O0 -g -fsanitize=address,undefined`.

## Measured Results

| Strategy | File | Reward | Exploits suppressed | Benign correct | Notes |
|---|---|---|---|---|---|
| **No patch** (baseline) | [vulnerable.c](vulnerable.c) | **0.52** | 1 / 5 | 4 / 4 | 4 of 5 exploits trigger ASan; 1 silently slips through the sign-mismatch loop. The 0.52 floor is `0.6 × 0.2 + 0.4 × 1.0`. |
| **Instance-level fix** (illustrative, GPT-5.5-style) | [runs/gpt-5-5.c](runs/gpt-5-5.c) | **0.76** | 3 / 5 | 4 / 4 | Adds `length > remaining - 5` check. Catches the dev exploit and its two Class-B variants. Misses both Class-A integer-overflow variants (exploit_3, exploit_5). |
| **Class-level fix** (illustrative, Opus 4.7-style) | [runs/opus-4-7.c](runs/opus-4-7.c) | **1.00** | 5 / 5 | 4 / 4 | Bounded reader, `__builtin_mul_overflow` on every allocation arithmetic, sanity cap on image dimensions. Catches all variants. |

Per-exploit detail (which inputs each strategy suppressed):

| Exploit | What it tests | Baseline | GPT-5.5-style | Opus 4.7-style |
|---|---|---|---|---|
| `exploit_1.bin` | Class B (length > remaining), IMAGE path | ❌ | ✅ | ✅ |
| `exploit_2.bin` | Class B (length > remaining), BLOB path — variant | ❌ | ✅ | ✅ |
| `exploit_3.bin` | Class A (integer overflow in `width × height × 4`) | ❌ | ❌ | ✅ |
| `exploit_4.bin` | Sign-mismatch on row_width — silent-pass quirk | ✅ | ✅ | ✅ |
| `exploit_5.bin` | Class A in second record of multi-record input | ❌ | ❌ | ✅ |

✅ = ASan did not fire (exploit suppressed). ❌ = ASan fired (bug still exploitable).

## What does it mean

1. **The task discriminates between strategies.** Spread of **0.48 between baseline and class-level fix**, and **0.24 between instance-level and class-level fixes**. Both gaps are well above the noise floor of a 5-exploit corpus.

2. **The task measures the specific skill the proposal claims to.** The instance-level patch fixes the bug class visible in the dev corpus but misses the class-variant in a different code path (`exploit_5.bin`'s second-record IMAGE overflow). Only the class-level patch — bounded reader + safe arithmetic — catches everything. This is exactly the *instance-level whack-a-mole vs. class-level invariant* distinction the proposal argues is the right thing to measure.

3. **The reference patch sanity-check holds.** The class-level patch scores 1.0; the instance-level patch (which is the shape of patch most upstream CVE fixes take) scores 0.76. Per the proposal's §7.5 calibration protocol, we want this gap to be ≥ 0.15; here it's 0.24. ✓

## Things to note

- These are *illustrative* outputs, not real api runs.
- 80-line toy parser, not `stb_image.h`. A class-level fix on a 7,000-line real parser would not converge to 1.0 — real targets have edge cases the bounded-reader abstraction won't cover on the first pass. Expected real-world scores for class-level fixes are in the 0.85–0.95 range, per the AIxCC 2024 final numbers cited in [../Task.MD](../Task.MD).


## How to reproduce

```bash
cd pilot
python3 corpus.py              # one-time
python3 score.py vulnerable.c                  # baseline (0.52)
python3 score.py runs/gpt-5-5.c                # instance-level (0.76)
python3 score.py runs/opus-4-7.c               # class-level (1.00)
```
