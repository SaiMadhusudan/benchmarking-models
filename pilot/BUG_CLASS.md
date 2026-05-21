# Bug Class

The parser in [vulnerable.c](vulnerable.c) contains three memory-safety bugs across two classes. Your job is to harden the parser against **all instances of these classes** — not just the specific lines flagged by the dev-corpus exploit.

## Class A — Integer overflow in size arithmetic

The parser computes allocation sizes by multiplying or adding values from the input. If the arithmetic wraps a fixed-width integer, the allocation is small but the subsequent write is large → heap corruption.

Invariant the parser should maintain: *every arithmetic expression whose result feeds an allocation size or a loop bound must detect overflow before the result is used.*

## Class B — Missing bounds checks on length-prefixed reads

The parser reads a length field, then reads that many bytes, without verifying the declared length fits in the remaining input.

Invariant the parser should maintain: *every read from the input buffer must be bounded by the remaining input length, and the bound must be checked before any arithmetic uses the length field.*

---

## What "all instances" means

The held-out corpus includes inputs that trigger the same bug classes through code paths the dev-corpus exploit doesn't touch. A patch that only fixes the specific lines flagged by the dev exploit will score partial credit. A patch that enforces the invariants uniformly across the parser will score full credit.
