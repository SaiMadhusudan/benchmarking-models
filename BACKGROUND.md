# Background: Memory Safety in 20 Minutes

This document is the primer for anyone reading [TASK.MD](TASK.MD) who isn't already deep in security work. It explains the concepts and tooling the proposal relies on, in the order they show up. If you've read the Project Zero blog for fun, you can skip this — it's aimed at engineers and reviewers who haven't.

---

## 1. What "memory safety" actually means

A program is **memory-safe** if it can't access memory it isn't supposed to. In a memory-safe language (Java, Python, Rust, Go, Swift), the language and runtime *guarantee* this — out-of-bounds array access throws an exception or fails to compile; a freed pointer can't be dereferenced.

C and C++ make no such guarantee. The programmer is responsible for:

- Allocating buffers the right size.
- Not reading or writing past the end of those buffers.
- Not freeing the same pointer twice.
- Not using a pointer after the memory it points to has been freed.
- Not letting arithmetic on length / size / index values wrap around (e.g. a 32-bit `width * height` that silently overflows).

When the programmer gets any of this wrong, the program enters a state called **undefined behavior**. On a good day, undefined behavior crashes the program. On a bad day, an attacker who can shape the input that triggers the undefined behavior can corrupt memory in a way that gives them code execution — i.e., they get to run their own code inside your process.

The whole field of **memory-safety vulnerabilities** is the study and exploitation of these gaps.

---

## 2. The four bug classes the task targets

The proposal scopes itself to four canonical bug classes. Each is the root cause of thousands of historical CVEs.

### 2.1 Integer overflow

```c
uint32_t width  = read_u32_from_input();
uint32_t height = read_u32_from_input();
uint32_t bytes  = width * height * 4;        // RGBA: 4 bytes per pixel
uint8_t* buf    = malloc(bytes);
read_bytes(buf, width * height * 4);          // BUG: writes past `bytes` if multiplication wrapped
```

If `width = 0x10000` and `height = 0x10000`, then `width * height = 0x100000000` — which doesn't fit in 32 bits and wraps to 0. `malloc(0)` returns a tiny buffer (or NULL); the subsequent `read_bytes` writes 4 GiB into it. Heap corruption follows.

### 2.2 Missing bounds check on length-prefixed data

```c
uint32_t chunk_size = read_u32_from_input();
char     buffer[chunk_size];                  // BUG: no check that chunk_size is sane
read_bytes(buffer, chunk_size);
```

The format declares its own chunk size in the file. The parser trusts that number. An attacker writes a file with `chunk_size = 0xFFFFFFFF`, the parser allocates a huge buffer (or reads off the end of the actual input data), and out-of-bounds memory is read or written.

### 2.3 Sign / unsigned mismatch

```c
int      offset      = read_signed_offset();
size_t   buffer_size = 1024;
if (offset < buffer_size) {                   // BUG: int promoted to unsigned, -1 becomes huge
    buffer[offset] = ...;
}
```

When you compare a `signed int` to a `size_t` (unsigned), C promotes the signed value to unsigned. A `-1` becomes `0xFFFFFFFF`, which is *not* less than 1024 in unsigned comparison, so the check passes. The subsequent `buffer[offset]` is way out of bounds.

### 2.4 Type confusion

```c
struct chunk_header { uint32_t type; uint8_t payload[]; };
// ...
if (header->type == TYPE_FOO)
    process_as_foo((struct foo*)header->payload);
else
    process_as_bar((struct bar*)header->payload);
```

If the parser's idea of `type` can diverge from what the payload actually is — because the payload was written before the type tag, or because the tag is in a different part of the file that an attacker can rewrite mid-parse — the parser will interpret bytes as fields they aren't, leading to reads and writes at attacker-chosen offsets.

---

## 3. Tooling the verifier (and the agent) use

### 3.1 Sanitizers

A **sanitizer** is a compile-time instrumentation that detects memory-safety bugs at runtime. The verifier in this task builds the parser with sanitizers and considers any sanitizer report on a held-out exploit as "exploit successfully reproduced" — and any sanitizer report on a held-out benign input as "patch broke something."

The three main sanitizers in the GCC / Clang world:

- **AddressSanitizer (ASan)** — catches out-of-bounds reads/writes on heap, stack, and globals. Catches use-after-free. ~2× runtime slowdown. The workhorse for memory-safety work.
- **MemorySanitizer (MSan)** — catches reads of uninitialized memory.
- **UndefinedBehaviorSanitizer (UBSan)** — catches signed integer overflow, null-pointer dereference, alignment violations, and other C-undefined-behavior cases.

Sanitizers are *detection*, not *prevention*. They tell you a bug exists; they don't fix it. Shipping a sanitizer-instrumented binary in production is generally a bad idea (performance, attack surface from the sanitizer itself). This is why `RULES.md` in the proposal prohibits the agent from "using sanitizers as runtime guards" — that would be cheating, not fixing.

### 3.2 Fuzzing

A **fuzzer** generates large numbers of semi-random inputs and feeds them to a program, looking for crashes. The crashes (when the program is built with sanitizers) become candidate exploits. The major fuzzers:

- **AFL++ / AFL** — coverage-guided mutation-based fuzzer.
- **libFuzzer** — in-process fuzzer that's part of LLVM.
- **honggfuzz** — Google's fuzzer, used heavily on Chrome.
- **OSS-Fuzz** — Google-run continuous fuzzing service for open-source libraries. Has filed tens of thousands of bugs since 2016.

The held-out exploit corpus for this task will be sourced from a mix of (a) real CVEs against the target parser, (b) hand-crafted variants, and (c) fuzzer-generated inputs reduced to minimal reproducers.

### 3.3 CVEs and the disclosure process

A **CVE (Common Vulnerabilities and Exposures)** is a public identifier for a specific vulnerability — e.g., `CVE-2023-4863`. The CVE record contains a description, affected versions, and a link to the patch.

The standard lifecycle:

1. **Finder** discovers the bug (fuzzer, code audit, reverse engineering).
2. Finder reports it privately to the **maintainer**.
3. Maintainer writes a patch, often with feedback from the finder.
4. Patch ships, CVE is assigned, public disclosure happens (usually 30–90 days after report).
5. Linux distros and downstream consumers backport the patch.

For this task, "upstream patches" means the step-3 patches that are public on GitHub. The proposal's anti-cheat measures specifically target agents that try to look up and copy these patches — because copying the patch is exactly the *instance-level whack-a-mole* the task is designed to discourage. The point is to test whether the agent can derive the *class-level* fix itself.

---

## 4. Why C parsers in particular?

Parsers — code that turns bytes from the outside world into structured data — are where memory-safety bugs concentrate, for three reasons:

1. **The input is attacker-controlled.** Any field in the file or packet can be whatever the attacker wants.
2. **The parsing logic is complex.** Length-prefixed structures, recursive grammars, optional fields, compression, encryption — each layer is a new opportunity for the parser's assumptions to diverge from the data's actual structure.
3. **Parsers are everywhere.** Every image library, every video codec, every network protocol, every font shaper, every PDF reader is parsing untrusted bytes. Even a single bug in libwebp affects every browser, every Electron app, every messaging client (see [BLASTPASS](REFERENCES.md#:~:text=BLASTPASS) in REFERENCES.md).

This is why "harden a C parser" is such a load-bearing benchmark for security capability. It's the bread-and-butter work of the entire defensive-security industry.

---

## 5. Instance-level vs. class-level fixes

This distinction is the heart of the task. An example will make it concrete.

Suppose a CVE is reported: in `parser_handle_chunk()`, line 412, the parser reads a chunk size and then reads that many bytes without bounds-checking. Two possible patches:

**Instance-level fix** (~3 lines):
```c
// at line 411:
if (chunk_size > remaining_bytes) return -1;
```

This fixes the reported instance. It does nothing for the eleven *other* call sites in the same parser that have the same bug.

**Class-level fix** (~50 lines, plus a refactor):
```c
// new abstraction in a new header:
typedef struct { const uint8_t* p; size_t remaining; } reader_t;
static inline int reader_consume(reader_t* r, size_t n, const uint8_t** out) {
    if (n > r->remaining) return -1;
    *out = r->p; r->p += n; r->remaining -= n;
    return 0;
}
// every call site through the parser is then refactored to use the reader.
```

This fixes every instance of the bug class, including the ones that haven't been reported yet, because the invariant ("you can't read past the end of the input") is now enforced by the type system rather than by every individual call site. A new chunk-handling function added next year will use `reader_consume` and inherit the safety for free.

The proposal's scoring is calibrated so that the instance-level patch (or worse, the agent that just copies the public CVE patches) scores in the 0.6–0.7 range — visibly partial credit — while the class-level patch scores 0.85+.

---

## 6. Glossary

| Term | Definition |
|---|---|
| **ABI** | Application Binary Interface — how compiled code expects to be called (register usage, stack layout, return-value conventions). |
| **ASan** | AddressSanitizer — Clang/GCC instrumentation that detects heap/stack/global OOB accesses and use-after-free. |
| **bounded reader** | An I/O abstraction that makes it structurally impossible to read past the end of the input. The class-level fix archetype. |
| **CVE** | Common Vulnerabilities and Exposures — the public identifier for a specific reported vulnerability. |
| **fuzzer** | Tool that generates many semi-random inputs to a program looking for crashes. AFL++, libFuzzer, honggfuzz, OSS-Fuzz are the major ones. |
| **harness** | A small CLI wrapper around the target code that the verifier (and the agent) can run against single inputs. Not modifiable by the agent. |
| **heap overflow** | A write past the end of a heap-allocated buffer. The most common shape of exploit. |
| **integer overflow** | Arithmetic on a fixed-width integer that wraps around. Often the root cause of heap overflows (overflow → undersized allocation → write past end). |
| **OOB** | Out-of-bounds. As in "OOB read" or "OOB write." |
| **OSS-Fuzz** | Google-run continuous-fuzzing service for open-source libraries. Has filed tens of thousands of bugs. |
| **Project Zero** | Google's offensive-security research team. Publishes long-form exploit write-ups. |
| **RCE** | Remote Code Execution. The worst outcome of a memory-safety bug — an attacker can run their own code in your process from across the network. |
| **sanitizer** | A compile-time instrumentation that detects memory-safety bugs at runtime (ASan, MSan, UBSan). |
| **UAF** | Use-after-free. Dereferencing a pointer to memory that has already been `free()`d. |
| **upstream patch** | The fix the original maintainer wrote and shipped, available publicly on GitHub once the CVE is disclosed. The proposal's anti-cheat measures specifically target agents that try to copy these. |

---

If anything in [TASK.MD](TASK.MD) is still unclear after reading this, the deepest source for any specific topic is in [REFERENCES.md](REFERENCES.md). Project Zero's blog, the OSS-Fuzz documentation, and the LangSec movement's papers are the three best-quality entry points into the field.
