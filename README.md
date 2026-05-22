# FrontierSWE Task Proposal: Memory-Safety Hardening of a Real-World C Parser

A new task for [FrontierSWE](https://www.frontierswe.com) in a category they don't currently have: **defensive security**. The agent is given a real, vulnerable C parser and must produce a class-level hardening patch that suppresses held-out exploits without breaking held-out benign inputs, within a performance budget.

**Author:** Sai Madhusudan Gunda — gundasaimadhusudan@gmail.com
**Repo:** https://github.com/SaiMadhusudan/benchmarking-models

---

## Why read this

FrontierSWE currently covers performance engineering, novel implementation, and ML research [[1]](REFERENCES.md). It doesn't cover **adversarial code reading** — the specific skill of looking at code and asking *"where could this go wrong under hostile input?"* That's the skill that distinguishes a Project Zero researcher from a competent application developer, and there's no public long-horizon benchmark for it.

This proposal fills that gap with a task that:

- **Slots cleanly into the existing FrontierSWE rubric** — hard-fail correctness gate plus a continuous 0–1 reward, modeled on the pyright optimization task.
- **Resists the standard GitHub-search shortcut** — the agent doesn't know which CVEs are in scope, the held-out exploits include hand-crafted class-variants the upstream patches miss, and the FrontierSWE runtime already disables internet access.
- **Discriminates between instance-level fixes and class-level fixes** — exactly the distinction that separates a strong security engineer from a weak one, and that we have no current way to measure agents on.

The DARPA AI Cyber Challenge 2024 results (winning systems patched 68% of synthetic vulnerabilities across 54M LoC) are the strongest evidence the task is in the right difficulty zone: feasible for state-of-the-art systems, not solved.

---

## Repo map

| File | What it is |
|---|---|
| [TASK.MD](TASK.MD) | **The proposal itself.** 11 sections covering the task design, motivation, target selection, scoring formula, anti-cheating, calibration, and pilot timeline. Start here. |
| [BACKGROUND.md](BACKGROUND.md) | A 20-minute primer on memory safety — sanitizers, fuzzers, CVE disclosure, the four bug classes in scope, and the instance-level vs. class-level distinction. Read this first if you're not already deep in security work. |
| [REFERENCES.md](REFERENCES.md) | Every numbered citation in [TASK.MD](TASK.MD), with a primary-source link and a one-line note on what it supports. Microsoft's 70% stat, BLASTPASS, AIxCC, ONCD, OSS-Fuzz, the FrontierSWE task templates I'm modeling on — all here. |
| README.md | You are here. |

---

## How to read in 10 minutes

1. **This README** — what the task is and why it's missing from the benchmark.
2. **[TASK.MD §1 and §6](TASK.MD#1-the-task)** — the task statement and the scoring formula. Two pages.
3. **[TASK.MD §7](TASK.MD#7-anti-cheating)** — anti-cheating, the most security-sensitive part of the design.

---

## How to read in full

Top to bottom: [BACKGROUND.md](BACKGROUND.md) → [TASK.MD](TASK.MD) → spot-check claims in [REFERENCES.md](REFERENCES.md).

The proposal includes a 6-week pilot timeline (TASK.MD §11) and a specific list of asks of the FrontierSWE team. Happy to discuss any of it — `gundasaimadhusudan@gmail.com`.
