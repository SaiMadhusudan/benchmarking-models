# Tiny Pilot

A one-hour proof-of-calibration for the [proposal](../Task.MD). No Docker, no API keys, no FrontierSWE harness — just a small vulnerable C file, a corpus, a scoring script, and a chatbot.

## What this is

- **[vulnerable.c](vulnerable.c)** — ~80 lines of C. A toy TLV (type-length-value) parser with 3 deliberate memory-safety bugs (one from each class in [BUG_CLASS.md](BUG_CLASS.md)).
- **[prompt.md](prompt.md)** — the instruction you paste into Claude.ai or Codex-in-VS-Code along with `vulnerable.c`.
- **[corpus.py](corpus.py)** — generates the test inputs (deterministic — run once).
- **[score.py](score.py)** — builds the patched C under `-fsanitize=address,undefined`, runs the held-out corpus, prints a score.
- **[RESULTS.md](RESULTS.md)** — table to fill in.

Everything is small on purpose. The point isn't to ship a benchmark; the point is to show Evan that the task design discriminates between agents — three numbers in a table is enough.

## How to run, end to end

You need `gcc` or `clang` and Python 3. Both ship with macOS / VS Code dev environments.

```bash
cd pilot
python3 corpus.py                              # writes corpus/dev/*.bin and corpus/held_out/*.bin
python3 score.py vulnerable.c                  # baseline score (should be ~0 — bugs are real)
```

Now for each agent:

1. Open a fresh chat (Claude.ai, ChatGPT, or Codex in VS Code).
2. Paste the contents of [prompt.md](prompt.md).
3. Paste the contents of [vulnerable.c](vulnerable.c) right after it.
4. Optionally paste the dev-corpus exploit (`corpus/dev/exploit_dev.bin` — as a hex dump) so the agent can see one concrete instance.
5. Let it work. Copy the final patched C into `runs/<agent>.c`.
6. Run `python3 score.py runs/<agent>.c`.
7. Append the score to [RESULTS.md](RESULTS.md).

Time per agent: ~15–30 minutes. Three agents = under two hours.

## What to send Evan

The repo link and the filled-in [RESULTS.md](RESULTS.md) table. That's it. The table shows the score spread; the patched C files show what each agent actually did; the gap between the agents and the reference patch shows whether the task discriminates.

## Limits of this pilot (be honest with Evan)

- It's an 80-line toy parser, not `stb_image.h`. Scaling up the corpus and the target is the next step if the calibration looks promising.
- Agents run interactively in a chat, not in a 20-hour sandboxed harness.
- The held-out corpus has 5 exploits, not 30. Statistical noise will be visible.

This is enough to answer "is the task design sound?" — not enough to publish a leaderboard number. Which is exactly what a proposal pilot should be.
