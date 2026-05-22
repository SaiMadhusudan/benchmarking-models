# Prompt

Copy everything between the lines below (including the C source at the end) into a fresh chat. Do not include this header line.

---

You are working on a defensive-security hardening task. You will be given a small C parser that contains memory-safety bugs across two classes. Your job is to produce a patched version of the C file that:

1. Suppresses the bug **classes**, not just the specific instances visible in the example input below. There will be held-out test inputs that trigger the same root causes through different code paths and combinations; a patch that only fixes the example will score partial credit.
2. Preserves the parser's behavior on benign inputs — same exit code, same `printf` output.
3. Stays in C (no other languages, no calling external libraries beyond what's already used).

The two bug classes are:

**Class A — Integer overflow in size arithmetic.** The parser computes allocation sizes by multiplying or adding values from the input. If the arithmetic wraps a fixed-width integer, the allocation is small but the subsequent write is large → heap corruption. Invariant to enforce: every arithmetic expression whose result feeds an allocation size or a loop bound must detect overflow before the result is used.

**Class B — Missing bounds checks on length-prefixed reads.** The parser reads a length field, then reads that many bytes, without verifying the declared length fits in the remaining input. Invariant to enforce: every read from the input buffer must be bounded by the remaining input length, checked before the length is used in arithmetic.

Constraints:

- You may refactor the parser freely — adding helper functions (safe-arithmetic wrappers, bounded-reader struct, etc.) is encouraged.
- You may not use `__attribute__((no_sanitize_address))` or otherwise disable sanitizers — the verifier builds with AddressSanitizer and UndefinedBehaviorSanitizer and any sanitizer report on a held-out exploit counts as a failure to suppress.
- You may not call out to a different image library or replace the parser logic with something fundamentally different.
- Aim for an architectural fix (e.g. a bounded reader + safe-arithmetic helpers applied uniformly), not per-line bounds checks. The held-out corpus is designed so that per-line fixes score lower than uniform invariants.

Output: produce a single complete patched C file. Include a 5-sentence note at the top of the file describing the invariant(s) you enforced and where.

Here is one example input that visibly triggers a bug (the held-out corpus includes other exploits in the same classes that you have not seen):

```
hexdump -C corpus/dev/exploit_dev.bin
00000000  02 14 00 00 00 00 00 10  00 00 00 10 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00  00                       |.........|
```

Here is the parser source:

```c
{{ PASTE THE CONTENTS OF vulnerable.c HERE }}
```

Produce the patched version now. Work autonomously; do not ask for clarification.
