# FrontierSWE Task Proposal
## Memory-Safety Hardening of a Real-World C Parser

**Author:** Sai Madhusudan Gunda — gundasaimadhusudan@gmail.com
**Companion docs:** [BACKGROUND.md](BACKGROUND.md) (memory-safety primer) · [REFERENCES.md](REFERENCES.md) (citations for every claim)

---

## Executive Summary

I'm proposing a new task in a category FrontierSWE doesn't currently have: **defensive security**. The agent receives a real, vulnerable C parser pinned to a historical commit, a description of the bug class present, and a small development corpus. It must produce a diff that suppresses a held-out corpus of exploits while preserving byte-identical output on a held-out corpus of benign inputs, within a performance budget. Grading is continuous in [0, 1] with a sharp correctness gate, matching the existing FrontierSWE rubric.

The task is resistant to the standard GitHub-search shortcut: the agent doesn't know which CVEs are in scope, the held-out exploit corpus contains hand-crafted variants of the same root-cause class that upstream patches typically don't catch, and the FrontierSWE runtime denies internet access [1]. The rest of this document goes deep on motivation, target selection, grading design, anti-cheating, calibration, and what success looks like — because the right framing of this task is the whole work.

**Origin:** the idea came from listening to *FFmpeg: The Incredible Technology Behind Video on the Internet* on Lex Fridman Podcast #496, where the maintainer described how the day-to-day work of FFmpeg is largely defending a C parser against adversarial input from the open internet [2].

---

## 1. The Task

The agent receives a real, vulnerable parser written in C — a media or binary-format parser pinned to a historical commit that contains multiple documented memory-safety vulnerabilities. It is given:

- The source code of the parser at the chosen commit.
- A description of the **class** of bugs in scope (for example, out-of-bounds reads caused by missing bounds checks on length fields, plus integer overflow in arithmetic involving dimension fields that feed into allocations or loop bounds).
- A small development corpus of benign inputs and a handful of malicious example inputs that visibly trigger sanitizer reports, so the agent can see the bug class concretely.
- A harness that invokes the parser on a single input file and exits non-zero on parse failure.
- A performance budget (within 10% of the original on geometric-mean throughput across the benign corpus).
- A `RULES.md` listing prohibited mechanisms (no swapping in a different parser, no disabling the harness, no using sanitizers as runtime guards, no adding a memory-safe language to the build).

The agent **does not receive**: the held-out exploit corpus, the held-out benign corpus, the list of specific CVEs in scope, or the upstream patches.

The agent produces a diff against the base commit, plus an optional 500-word `SOLUTION.md` describing the architectural approach (used only for qualitative analysis, not for scoring).

A verifier applies the diff, builds the parser under sanitizers, runs both held-out corpora, runs a performance benchmark, and produces a composite score in [0, 1].

---

## 2. Why This Matters

### 2.1 What memory-safety vulnerabilities actually are

When C code parses untrusted input — an image file from the web, a network packet, a font embedded in a PDF, a video stream — the parser has to read length fields, allocate buffers, copy data, advance pointers, and walk recursive structures. A defect in this code lets a crafted input induce memory corruption. The four canonical instances:

- **Integer overflow into allocation.** The parser reads `width` and `height` from a file header and computes `width * height * 4` as the allocation size for an RGBA buffer. If the multiplication wraps a 32-bit integer, the parser allocates a small buffer and then writes a much larger amount of pixel data into it.
- **Missing bounds check on length-prefixed data.** The parser reads a 32-bit chunk size, then reads that many bytes into a local buffer, without first verifying that the declared size fits in the remaining input. The result is an out-of-bounds read.
- **Sign/unsigned mismatch.** The parser compares an attacker-supplied signed offset to a buffer size as if both were unsigned. A negative offset compares as a large positive value, the bounds check passes, and the subsequent access goes out of bounds.
- **Type confusion at protocol boundaries.** The parser dispatches on a type tag and processes the payload as one of several structures. If the tag is mutable after dispatch, or if the dispatched-to handler doesn't re-verify the payload type, the parser reads or writes the wrong fields.

Each of these classes has dozens to thousands of historical instances. They are the bread-and-butter of vulnerability research. (See [BACKGROUND.md](BACKGROUND.md) for a primer on the underlying tooling — sanitizers, fuzzers, and the CVE process — if any of this is unfamiliar.)

### 2.2 The economic and operational reality

Microsoft has stated publicly, repeatedly, that **roughly 70% of the CVEs it patches are memory-safety bugs in C/C++ code** (originally from Matt Miller's BlueHat IL 2019 talk; the figure has held steady since) [3]. Google has reported similar numbers for Android and Chrome [4]. These two organizations together represent a meaningful fraction of the world's attack surface, and they are unambiguous about where the bugs come from.

Project Zero — Google's offensive security research team — maintains a public spreadsheet of "0-day exploits detected in the wild" [5]. A large majority of the entries are memory-safety bugs in parsers (image parsers, font parsers, video parsers, font shaping libraries, JavaScript-engine JIT compilers). The dollar value of the underlying bugs, on the gray market, runs from low six figures to over a million dollars per chain for the highest-tier targets (iOS, Android, Chrome) [6].

Google's OSS-Fuzz project, which has been running continuous fuzzing against open-source libraries since 2016, has filed and tracked **tens of thousands** of bugs across the libraries it covers [7]. The overwhelming majority are memory-safety defects in C/C++ parsers. OSS-Fuzz finds them faster than maintainers fix them; there is a continuous backlog.

**CVE-2023-4863 in libwebp** — the BLASTPASS chain — is a good recent illustration. A single integer overflow in WebP's Huffman code decoder gave attackers remote code execution against Chrome, Firefox, Edge, Safari, Electron-based apps, 1Password, Signal, Telegram, and iMessage, because all of those products link against the same library. It was exploited in the wild as a zero-click iMessage attack delivering NSO Group's Pegasus spyware [8]. The patch was a small bounds check; the blast radius was global. This is the typical asymmetry of the field — small bugs, massive impact.

### 2.3 The industry around it

There are three groups working in this space, with different incentives and different products.

**Finders** are the offensive side. Google's Project Zero, the various national signals-intelligence offensive teams, private firms like Trail of Bits, NCC Group, Quarkslab, and Margin Research, plus bug-bounty hunters operating through HackerOne, Bugcrowd, and vendor-specific programs. Academic labs (UCSD, CMU, ETH Zürich) run continuous fuzzing campaigns and publish papers about the techniques. The tools they use are well-documented: AFL++, libFuzzer, honggfuzz, KLEE, angr, CodeQL queries, semantic differential analysis, and large amounts of GDB. The skill set is reverse engineering plus deep understanding of compiler behavior plus a particular taste for adversarial thinking.

**Fixers** are the defensive side, on the receiving end of CVE reports. Maintainers of widely-used libraries — libpng, libjpeg-turbo, libxml2, FreeType, FFmpeg, OpenSSL, zlib — plus the security-response teams at Linux distros (Red Hat, SUSE, Debian, Canonical), at major vendors (Apple, Google, Microsoft), and at cloud providers. Their job is to take a reported bug, write a patch that fixes it without breaking anything else, get the patch through review and CI, and ship it through the distribution chain. The Linux Foundation's Alpha-Omega project specifically funds this work for the most-critical-but-least-funded libraries [9]. OpenSSF's Best Practices badge program is partially about whether maintainers have credible processes for this [10].

**Replacers** are the structural side. They argue (correctly, for the long term) that the right answer is to stop writing parsers in C/C++ and move to memory-safe languages — Rust, Go, Swift, or carefully-constrained subsets. Mozilla rewrote parts of Firefox's media stack in Rust starting around 2017 [11]. Cloudflare moved their TLS path to Rust [12]. Microsoft has stated they're moving parts of the Windows kernel in this direction over the next decade [13]. The 2024 ONCD report *Back to the Building Blocks: A Path Toward Secure and Measurable Software* explicitly calls for memory-safe rewrites of critical infrastructure [14]. CISA's Secure-by-Design Pledge, which over 250 companies have signed, includes commitments around memory safety [15].

The Replacers are right about the long-term trajectory but wrong about the timeline. The C and C++ codebase that the world's software is built on is too large to rewrite in any near-term horizon. The Linux kernel is around 30 million lines. Chromium is around 35 million. The combined open-source C corpus that has untrusted input as part of its job description is in the high hundreds of millions of lines. Even if every new project after 2025 were written in Rust, the existing code stays in service for decades.

### 2.4 Why hardening is daily work

Given the rewrite timeline, the actual day-to-day reality of defensive security work is: a CVE drops, the maintainer has to write a patch, the patch ships through distros, and the cycle repeats. Multiply this by hundreds of libraries and you get the rhythm of modern security response.

The interesting engineering question — and the heart of this proposed task — is **what does a good patch look like, versus a bad one?**

A **bad** patch fixes the specific reported instance. The same root cause re-emerges through an adjacent code path the next month, the same researcher reports it again, and the maintainer plays whack-a-mole for years. This is the typical pattern in libraries that don't have strong architectural invariants.

A **good** patch identifies the underlying invariant the parser should maintain — for example, *"every read from the input buffer must be bounded by the declared chunk size, and the declared chunk size must be verified against the remaining input length before any arithmetic is done with it"* — and enforces that invariant at the right architectural level, typically at the I/O boundary. This kills the whole class of bugs, not just the reported one. Examples of this style include modern libxml2's entity-expansion limits, Chromium PDFium's bounded-reader architecture [16], the `wuffs` language whose entire type system enforces parser safety [17], and Mozilla's `mp4parse-rust` which replaced libstagefright not by porting line-by-line but by re-architecting around invariants [18].

This distinction — class-level hardening versus instance-level whack-a-mole — is exactly what we're testing. A weak agent will whack moles. A strong agent will find the invariant.

### 2.5 What we learn about agents

This task tests something current benchmarks don't really hit. SWE-bench Pro tests whether agents can resolve specific GitHub issues, which is close to *"implement what the maintainer would have implemented."* Terminal-Bench tests short-horizon execution. The existing FrontierSWE tasks test performance optimization, novel implementation, and ML research [1]. None of them test the specific skill of **reading code adversarially** — looking at it from the perspective of *"where could this go wrong under hostile input"* rather than *"does this implement the intended functionality."*

That skill is one of the most valuable engineering capabilities that exists in the human population. It's the difference between a senior security engineer at Project Zero and a competent application developer. If we want to know whether agents can do it, we need a benchmark that measures it, and right now nothing does at the long-horizon scale FrontierSWE is built for.

The DARPA AI Cyber Challenge in 2024 is the closest reference point: teams built systems that automatically find and patch bugs in C code, and the winning systems found and patched a meaningful fraction of synthetic vulnerabilities across 54 million lines of code [19]. AIxCC is a closed competition with specific infrastructure; FrontierSWE is a public benchmark anyone can run a model against. The AIxCC results suggest this task is in the right zone — feasible for state-of-the-art systems but not solved.

---

## 3. Target Selection

The choice of target parser is the entire task. A weak choice makes it trivial; the wrong kind of difficulty makes it intractable. Selection criteria, in priority order:

1. **Size.** Small enough that an agent can read it end-to-end in its context. ~5k–10k lines.
2. **Self-contained.** No or minimal external dependencies, so the verifier sandbox is reproducible and the agent isn't fighting a build system.
3. **Real CVE history.** At least 5–10 documented memory-safety CVEs in the bug class we choose, so we have material for the held-out exploit corpus and the upstream patches we don't want copied.
4. **Not too famous.** Avoid parsers where a model might have seen the specific patches in pre-training. Mid-tier, embedded-systems parsers are better than libpng.
5. **Benign-corpus availability.** A large public dataset of valid inputs in the target format, so the benign held-out corpus is realistic and broad.
6. **Language scope.** Strictly C (no C++). This narrows the failure modes and keeps the verifier toolchain simple.

### 3.1 Primary candidate: `stb_image.h` at a 2018-era commit

**Reasoning:** ~7,000 lines, single header file, zero dependencies. Many documented memory-safety issues filed between 2017 and 2021, mostly OOB reads in the PNG/BMP/TGA paths and integer overflows in the dimension-arithmetic paths [20]. Widely used in game development and embedded systems, so the benign corpus is abundant (any public dataset of game assets works). Old enough that the agent won't have memorized the exact patches; specific enough that the bug class is sharp.

### 3.2 Backup candidates

- **libwebp** (at a pre-CVE-2023-4863 commit) — high real-world impact, good for the integer-overflow class.
- **giflib** — small, simple, with documented OOB-read history.
- **libcoap** — network parser, different bug-class flavor (protocol-state-machine bugs).
- **tinydtls** — DTLS implementation, mixes parser and cryptographic state.

### 3.3 Pilot plan

Two candidates, parallel setup, ~1 week each. Confirm: **(a)** the CVE record actually contains the bug classes I claim, **(b)** reproducing the exploits is mechanically feasible, **(c)** the benign corpus assembles cleanly, **(d)** a reference patch I can write in a day scores ≥0.9 against the corpus. Whichever candidate clears these bars first becomes the final target; the other remains as backup in case calibration on the first reveals it's too easy or too hard.

---

## 4. What The Agent Receives

The repository given to the agent contains:

- `target/` — the parser source code at the pinned commit, with a build script that produces both a normal binary and a sanitizer-instrumented one.
- `harness/` — a single-input CLI that reads a file path, runs the parser, writes output to stdout (or a temp file), and exits non-zero on parse failure. The verifier runs this exact harness; the agent is forbidden from modifying it.
- `dev_corpus/valid/` — ~50 valid input files representative of real-world inputs in the target format. The agent can use these freely for testing.
- `dev_corpus/malicious/` — ~10 malicious inputs that visibly trigger sanitizer reports against the original parser. These exist so the agent can see the bug class concretely and verify that its patch suppresses at least these specific instances. The agent will be tempted to overfit to these — that's intended, and the held-out corpus is the corrective.
- `dev_corpus/expected_outputs/` — for each valid dev input, the byte-exact output the original parser produces. Byte-identical match is the correctness criterion. Includes both parsed data and exit code.
- `BUG_CLASS.md` — a prose description of the bug class in scope. The phrasing of this document is one of the more sensitive calibration knobs (Section 8 discusses).
- `BENCHMARK.md` — performance target description, including the corpus the microbenchmark uses (a subset of the benign corpus), the timing methodology, and the regression tolerance.
- `RULES.md` — explicit constraints. No replacing the parser. No disabling the harness. No invoking external parsers. No sanitizer suppressions or `__attribute__((no_sanitize_address))`. No adding a non-C language to the build. No exception-style control flow via `setjmp`/`longjmp` introduced for the purpose of evading sanitizer reports. The agent stays in C.

The agent **does not** receive: the held-out exploit corpus, the held-out benign corpus, the specific CVE numbers in scope, or the upstream patches.

---

## 5. What The Agent Produces

A diff against the base commit, containing:

- Modifications to the parser's source files. These can be arbitrarily large in scope — a single-line bounds check or a full refactor of the I/O layer, both valid.
- Optionally, new `.c` / `.h` files containing helper code: bounds-checking wrappers, safe-arithmetic helpers, a bounded-reader abstraction, an explicit allocator wrapper. These must link into the parser binary, not exist as external runtime dependencies.

---

## 6. Scoring

Composite reward in [0, 1], with a sharp correctness gate matching FrontierSWE convention [21].
Working on This 

### 6.1 Hard-fail gates (any failure → reward 0)

### 6.2 Continuous score (if all gates pass)

### 6.3 Subscores

---

## 7. Calibration

The phrasing of `BUG_CLASS.md` is the single most sensitive calibration knob. Too specific ("there is an integer overflow on line 412 of stb_image.h when processing PNG IHDR width fields") and the task degenerates into a guided patch. Too vague ("there are memory safety bugs somewhere") and the task degenerates into adversarial auditing of the entire codebase, which is a different (and much harder) task.

The right level is the **bug class**, in two or three sentences:

> *"The parser contains multiple instances of integer overflow in arithmetic involving header-derived dimensions and lengths that feed into allocation sizes or loop bounds, plus several instances of missing bounds checks on length-prefixed chunk reads. Both classes are exploitable as out-of-bounds writes or reads. Your task is to harden the parser against all instances of these classes, not just the ones visible in the dev corpus."*

This tells the agent what to look for without telling it where to look. A strong agent will read the I/O paths systematically and find the invariant. A weak agent will pattern-match on the dev corpus and miss the variants.

**Calibration protocol:**

1. Write the reference patch myself in one sitting (target: 1 day). Score it against the held-out corpora.
2. Score the "upstream-patch copy" attack (mechanically apply the public CVE patches).
3. Score the "naive overfitting" attack (an LLM agent given only the dev corpus, with no special prompting).
4. Adjust the held-out corpus, the bug-class phrasing, and the weights until: reference ≥ 0.85, upstream-copy ≤ 0.7, naive-overfit ≤ 0.5, and the gap between any two of these is ≥ 15 points.

If I can't hit those bars on the primary candidate, the backup candidate becomes the final target.

---

## 8. Relationship To Other Benchmarks And Existing FrontierSWE Tasks

### 8.1 SWE-bench and SWE-bench Pro

SWE-bench tests whether agents can resolve GitHub issues. The average solution is around 100 lines of code, the verification is the project's own test suite, and the work is fundamentally about implementing what the maintainer would have implemented. The skill being tested is implementation literacy plus code navigation.

This task tests something **orthogonal**: adversarial reading of code. The verification is held-out exploits, not project tests. The work isn't about matching maintainer intent — it's about preventing failure modes the original code didn't anticipate. An agent that's good at SWE-bench Pro is not automatically good at this; the skills correlate but the failure modes are different.

### 8.2 DARPA AIxCC

The DARPA AI Cyber Challenge in 2024 had a similar shape — teams built systems that automatically find and patch bugs in C code, and identified 86% / patched 68% of synthetic vulnerabilities at the final [19]. AIxCC is a closed competition with specific infrastructure and dedicated cyber-reasoning-system harnesses; FrontierSWE is a public benchmark anyone can run a frontier model against using a generic coding-agent harness. The AIxCC results are the strongest evidence that this task is in the right difficulty zone: feasible for state-of-the-art systems but very much not solved.

### 8.3 The existing FrontierSWE tasks

Looking at the published 17 [1]:

- **`pyright-type-checking-optimization`** — performance engineering with a sharp correctness gate. **Closest in shape to this task** — same "correctness must be perfect, then optimize" structure. The differences are the dimension being optimized (security vs. performance) and the held-out adversarial corpus (vs. held-out benchmarks).
- **`libexpat-to-x86asm`** — porting with strict tooling prohibitions. Different domain, but the anti-cheat patterns (encrypted verifier data, source-scan for verifier-path references) carry over directly.
- **`frogsgame-rl`** — ML research / post-training methodology. Different.
- **`postgres-sqlite-wire-adapter`** — novel implementation against a protocol spec. Closer to traditional SWE-bench but bigger scope.

This task slots cleanly into the implementation/performance category, with security as the optimization axis.

---

## 9. What Success Looks Like

A successful task release means:

- A frontier model trained for code, run with a 20-hour budget under the FrontierSWE harness, produces a diff that scores in the **0.4–0.7 range** on the composite reward. That's "useful, but not solved" — the same zone as the pyright task and the AIxCC final results.
- The score distribution across the published models has meaningful spread (≥ 0.2 between top and bottom of the leaderboard), so the task discriminates.
- At least one model produces a class-level patch (catches the variants), and at least one produces only an instance-level patch (misses them). The benchmark surfaces the distinction visibly in the subscores.
- The cheating-attempt rate is comparable to or lower than other FrontierSWE tasks [1], suggesting the anti-cheat countermeasures hold.

If all four hold, the task graduates into the next FrontierSWE release as the first "defensive security" entry, and the framing — class-level vs. instance-level hardening — gives the blog post a sharp story to tell.

---


*See [REFERENCES.md](REFERENCES.md) for every numbered citation. See [BACKGROUND.md](BACKGROUND.md) for a primer on the underlying tooling and concepts if any of this terrain is unfamiliar.*
