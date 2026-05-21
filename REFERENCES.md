# References

Every numbered citation in [TASK.MD](TASK.MD), with a primary-source link and a one-line note on what the source supports.

---

**[1] FrontierSWE blog post (Proximal Labs)** — the benchmark this proposal targets, including the 17 published tasks, the rubric design (continuous 0–1 with hard-fail gates), the observed cheating-attempt rate, and the no-internet sandbox.
https://www.frontierswe.com/blog

**[2] Lex Fridman Podcast #496 — *FFmpeg: The Incredible Technology Behind Video on the Internet*** — the origin of this proposal; the FFmpeg maintainer describes the daily work of defending a C parser against adversarial input.
https://lexfridman.com/ffmpeg (search the episode page for the segment on security work and CVE response)

**[3] Matt Miller, *Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape*, BlueHat IL 2019** — the original "70% of CVEs Microsoft patches are memory-safety bugs" stat. The figure has held steady in subsequent years.
- Talk video: https://www.youtube.com/watch?v=PjbGojjnBZQ
- MSRC follow-up post: https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/

**[4] Google security blogs on memory safety in Chrome and Android** — Google reports similar 70%-ish memory-safety fractions for Chrome and Android.
- Chromium: https://www.chromium.org/Home/chromium-security/memory-safety/
- Android: https://security.googleblog.com/2022/12/memory-safe-languages-in-android-13.html

**[5] Project Zero — *0day "In the Wild"* tracking spreadsheet** — public list of 0-day exploits Google has detected being used against real targets. A majority are memory-safety bugs in parsers.
https://googleprojectzero.github.io/0days-in-the-wild/

**[6] Zerodium / Crowdfense exploit-acquisition price lists** — public price sheets for full-chain mobile and browser exploits, showing the dollar value of memory-safety bugs.
- Zerodium: https://zerodium.com/program.html
- Crowdfense: https://www.crowdfense.com/exploit-acquisition-program/

**[7] Google OSS-Fuzz project** — continuous fuzzing of open-source libraries; has filed tens of thousands of bugs across its history, the majority memory-safety defects in C/C++.
- Project site: https://google.github.io/oss-fuzz/
- Bug tracker stats: https://bugs.chromium.org/p/oss-fuzz/issues/list

**[8] CVE-2023-4863 / BLASTPASS** — heap buffer overflow in libwebp's Huffman decoder, exploited as a zero-click iMessage attack delivering NSO Group's Pegasus spyware. Affected Chrome, Firefox, Safari, Edge, Electron apps, 1Password, Signal, Telegram, iMessage.
- NVD entry: https://nvd.nist.gov/vuln/detail/CVE-2023-4863
- Citizen Lab BLASTPASS disclosure: https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/
- Isosceles technical write-up: https://blog.isosceles.com/the-webp-0day/

**[9] Linux Foundation Alpha-Omega Project** — funds security work for critical-but-underfunded open-source libraries.
https://alpha-omega.dev/

**[10] OpenSSF Best Practices Badge Program** — assesses whether projects have credible security processes.
https://www.bestpractices.dev/

**[11] Mozilla Rust adoption in Firefox** — `mp4parse-rust` replaced libstagefright (2017); Servo/Stylo CSS engine; later media-stack components.
- Hacks blog overview: https://hacks.mozilla.org/2017/11/oxidation-mozillas-renewed-push-to-rust/
- mp4parse-rust: https://github.com/mozilla/mp4parse-rust

**[12] Cloudflare's TLS path rewrite in Rust** — `boringtun`, `quiche`, `pingora`.
- Pingora announcement: https://blog.cloudflare.com/pingora-open-source/
- quiche: https://github.com/cloudflare/quiche

**[13] Microsoft Rust-in-Windows efforts** — public statements from David Weston (CVP for Enterprise and OS Security) on rewriting Windows kernel components in Rust.
- BlueHat IL 2023 talk: https://www.youtube.com/watch?v=8T6ClX-y2AE

**[14] ONCD, *Back to the Building Blocks: A Path Toward Secure and Measurable Software* (Feb 2024)** — White House Office of the National Cyber Director report calling for memory-safe languages in critical infrastructure. Explicitly names the Morris worm, Slammer, Heartbleed, Trident, and BLASTPASS as memory-safety incidents.
- Report PDF: https://bidenwhitehouse.archives.gov/wp-content/uploads/2024/02/Final-ONCD-Technical-Report.pdf
- Press release: https://bidenwhitehouse.archives.gov/oncd/briefing-room/2024/02/26/press-release-technical-report/

**[15] CISA Secure-by-Design Pledge** — 250+ companies have committed to memory-safety roadmaps as part of CISA's voluntary pledge.
https://www.cisa.gov/securebydesign/pledge

**[16] Chromium PDFium's bounded-reader architecture** — internal design pattern that enforces bounds at the I/O layer rather than relying on per-call checks.
- Source tree: https://chromium.googlesource.com/chromium/src/+/main/pdf/

**[17] `wuffs` — Wrangling Untrusted File Formats Safely** — Nigel Tao's language whose entire type system is designed to make parser safety mechanical. Compiles to C.
https://github.com/google/wuffs

**[18] `mp4parse-rust`** — Mozilla's MP4 demuxer in Rust, designed around invariants rather than direct line-by-line porting of libstagefright.
https://github.com/mozilla/mp4parse-rust

**[19] DARPA AI Cyber Challenge (AIxCC) 2024 final results** — teams' systems identified 86% and patched 68% of synthetic vulnerabilities across 54M lines of code. Winners: Team Atlanta ($4M), Trail of Bits ($3M), Theori ($1.5M). All seven finalist systems are being open-sourced.
- DARPA announcement: https://www.darpa.mil/news/2025/aixcc-results
- Final winners page: https://aicyberchallenge.com/finals-winners-announcement/
- Team Atlanta: https://team-atlanta.github.io/

**[20] `stb_image.h` CVE / issue history** — documented memory-safety reports filed against `stb_image.h` between roughly 2017 and 2021, mostly OOB reads in PNG/BMP/TGA paths and integer overflows in dimension arithmetic.
- Repository: https://github.com/nothings/stb
- Issue tracker (filter on `security` / `crash`): https://github.com/nothings/stb/issues
- Past CVEs: https://nvd.nist.gov/vuln/search/results?form_type=Basic&search_type=all&query=stb_image

**[21] FrontierSWE pyright-type-checking-optimization task** — the structural model for this proposal: hard-fail gates (build / tests / diagnostic parity / anti-cheat) plus a continuous performance score (geometric mean of speedup ratios). Anti-cheat includes source-scans for verifier-internal path references.
https://github.com/Proximal-Labs/frontier-swe/tree/main/tasks/pyright-type-checking-optimization

**[22] FrontierSWE task template** — the layout every task in the FrontierSWE repo follows: `task.toml`, `instruction.md`, `job.yaml`, `environment/Dockerfile`, `tests/test.sh`, `tests/compute_reward.py`.
https://github.com/Proximal-Labs/frontier-swe

