# Pilot Results

After you run each agent and `score.py`, fill in this table. Commit it back to the repo, point Evan at it.

## Setup

- Target: [vulnerable.c](vulnerable.c) — 80-line TLV parser, 3 deliberate bugs across 2 classes.
- Held-out corpus: 4 benign + 5 exploits (1 instance-match with dev exploit, 4 class-variants).
- Scoring: `reward = 0.6 * exploit_suppression + 0.4 * benign_correctness`.
- Compiler: clang (or gcc) with `-fsanitize=address,undefined`.

## Results

| Agent | Wall clock | Reward | Exploits suppressed | Benign correct | Strategy observed |
|---|---|---|---|---|---|
| Baseline (no patch) | — | _expected 0.0_ | 0 / 5 | 4 / 4 | The bugs are real. |
| Reference patch (me, written by hand) | ~30 min | _fill in_ | _fill in_ | _fill in_ | Bounded reader + safe-arithmetic helpers applied uniformly. |
| Claude Opus 4.7 (Claude.ai) | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _e.g. "Instance-level: added 3 bounds checks at the exact lines flagged by the dev exploit; missed 3 variants."_ |
| Claude Sonnet 4.6 (Claude.ai) | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
| GPT-5.5 (Codex in VS Code) | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
| Trivial cheat: reject all images | _bounded ≤ 0.5_ | _fill in_ | 5 / 5 | _likely 1 / 4_ | Confirms the 0.6/0.4 weighting isn't gameable. |
| Upstream-style instance fix (only the dev exploit's line) | _bounded ≤ 0.7_ | _fill in_ | _likely 1-2 / 5_ | 4 / 4 | Confirms the held-out class-variants are doing their job. |

## What to write next to the table

A few sentences answering:

1. **Does the task discriminate between agents?** I.e., is the spread between the top and bottom agent ≥ 0.2? If yes, the task has signal.
2. **Does it discriminate between strategies?** I.e., does at least one agent produce a class-level patch (score ≥ 0.8) and at least one produce an instance-level patch (score ≤ 0.6)? If yes, the task measures the specific skill the proposal claims to.
3. **Do the cheat bounds hold?** I.e., do the trivial-cheat and upstream-copy rows score below the best legitimate agent? If yes, the anti-cheat design is sound at this scale.

If all three are yes, the proposal is well-calibrated and ready to scale to a real target like `stb_image.h`.

## Honest caveats (paste these into the email to Evan)

- 80-line toy parser, not a real production library. Real targets are 100× this size with proportional bug-class density.
- 5 held-out exploits is too few to be statistically robust. The numbers are directional.
- Agents run in a chat with no enforced sandbox or wall clock. Conditions differ from the production FrontierSWE harness.

These limitations are why this is a *proposal pilot* and not a benchmark release. They go away when the task is built on the real FrontierSWE infrastructure.
