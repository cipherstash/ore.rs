# Zeroize Audit Report

**Run ID:** `c212f1cdd302`
**Timestamp:** `2026-06-15T13:19:26Z` (assembled final: 2026-06-16)
**Repository:** `/Users/dan/Projects/CipherStash/ore.rs`
**Crate:** `ore-rs` v0.8.3 (manifest: `packages/ore-rs/Cargo.toml`)
**Compile DB:** none (Rust mode — crate root `packages/ore-rs/src/lib.rs`, TU hash `6f04dcee`)

**Configuration:**

| Setting | Value |
|---|---|
| Language mode | rust |
| Optimization levels | O0, O1, O2 |
| MCP mode | prefer |
| MCP available | yes (serena) |
| MCP required for advanced | yes |
| Assembly analysis | enabled (AArch64, experimental backend) |
| Semantic IR analysis | disabled |
| CFG analysis | disabled |
| Runtime tests | disabled |
| PoC generation | enabled |
| PoC validation | mandatory — completed, verified |

---

## Executive Summary

A single confirmed, medium-severity, secret-retention defect was found in the `ore-rs`
crate: `Aes128Prng` implements `Zeroize` but never triggers it on drop, leaving the
AES-CTR keystream (`data`) and position state (`ptr`/`ctr`) in the reclaimed stack
frame. The finding is corroborated by source, MIR, and LLVM-IR evidence and proven by a
verified, exploitable PoC (253/256 keystream bytes survive drop versus 0/256 with a
`ZeroizeOnDrop` control).

Two of the original source claims were narrowed by compiler evidence: the AES **key
schedule** is in fact wiped on drop by the `aes` crate's own `ZeroizeOnDrop` and that
wipe **survives O2 on both the normal and unwind paths** — it is **not** optimized away.
No `OPTIMIZED_AWAY_ZEROIZE`, `STACK_RETENTION`, `REGISTER_SPILL`, or `SECRET_COPY`
defects were confirmed.

| Metric | Count |
|---|---|
| Files scanned | 15 |
| Translation units analyzed | 1 of 1 |
| Sensitive objects identified | 6 |
| **Total findings** | **1** |

### By Severity

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 1 |
| Low | 0 |

### By Confidence

| Confidence | Count |
|---|---|
| Confirmed | 1 |
| Likely | 0 |
| Needs review | 0 |

### By Category

| Category | Count |
|---|---|
| MISSING_SOURCE_ZEROIZE | 1 |
| OPTIMIZED_AWAY_ZEROIZE | 0 |
| PARTIAL_WIPE | 0 |
| NOT_ON_ALL_PATHS | 0 |
| STACK_RETENTION | 0 |
| REGISTER_SPILL | 0 |
| SECRET_COPY | 0 |
| INSECURE_HEAP_ALLOC | 0 |
| MISSING_ON_ERROR_PATH | 0 |
| LOOP_UNROLLED_INCOMPLETE | 0 |
| NOT_DOMINATING_EXITS | 0 |

### PoC Validation

| Metric | Count |
|---|---|
| Total findings | 1 |
| PoCs generated | 1 |
| PoCs validated (compiled + ran) | 1 |
| PoCs verified (claim proven) | 1 |
| Exploitable (confirmed) | 1 |
| Not exploitable | 0 |
| Rejected | 0 |
| Compile failures | 0 |
| No PoC generated | 0 |
| Verification failures | 0 |

### MCP Availability and Impact

MCP (serena) was available and used. Because MCP was present, no MCP-unavailable
confidence downgrades were applied to the advanced categories (`SECRET_COPY`,
`MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS`). The one finding rests on three
independent non-MCP signals (source + MIR + IR) plus a verified PoC, so it would have
remained `confirmed` regardless.

---

## Sensitive Objects Inventory

| ID | Name | Type | Location | Confidence | Heuristic | Wipe Status |
|---|---|---|---|---|---|---|
| SO-5001 | OreAes128 | struct (prf1/prf2 PRF keys) | `packages/ore-rs/src/scheme/bit2.rs:34` | high | crypto_typed_field | OK — `derive(ZeroizeOnDrop)` → Drop; `rng` is `#[zeroize(skip)]` (correct) |
| SO-5002 | Aes128Prf | struct (aes::Aes128 key schedule) | `packages/ore-rs/src/primitives/prf.rs:7` | high | crypto_typed_field | OK — `derive(ZeroizeOnDrop)` → Drop |
| SO-5003 | Aes128Z2Hash | struct (aes::Aes128 keyed by RO nonce) | `packages/ore-rs/src/primitives/hash.rs:7` | high | crypto_typed_field | OK — `derive(ZeroizeOnDrop)` → Drop |
| SO-5004 | KnuthShufflePRP | struct (perm/inverse from PRP seed) | `packages/ore-rs/src/primitives/prp.rs:7` | high | crypto_typed_field | OK — Zeroize + manual Drop + ZeroizeOnDrop |
| SO-5005 | **Aes128Prng** | struct (aes::Aes128 + keystream) | `packages/ore-rs/src/primitives/prp/prng.rs:5` | high | crypto_typed_field | **FINDING (ZA-0001)** — manual Zeroize, no auto-trigger; data/ptr/ctr not wiped on drop |
| SO-5006 | SeedBuf | struct (key-equivalent PRP seeds) | `packages/ore-rs/src/scheme/bit2.rs:58` | high | sensitive_name_match (Seed) | OK — manual Drop zeroizes each AesBlock seed |

Five of the six sensitive objects have approved, correctly-triggered wipes. Only
`Aes128Prng` (SO-5005) has an incomplete, never-auto-triggered wipe — the subject of
ZA-0001. Plaintext/ciphertext types (`CipherText`, `Left`, `Right`, `RightBlock32`) and
the width/decompose modules were deliberately excluded from scope as non-secret.

---

## Findings

### Medium Severity

#### ZA-0001: MISSING_SOURCE_ZEROIZE — medium (confirmed)

**Location:** `packages/ore-rs/src/primitives/prp/prng.rs:5` (struct `Aes128Prng`; manual `zeroize` body at prng.rs:12-18; construction at prng.rs:24-36)
**Object:** `Aes128Prng` (SO-5005) — `cipher: aes::Aes128`, `data: [GenericArray<u8,U16>;16]` (256 bytes, stack-inline keystream, struct offset 0..256), `ptr: (usize, usize)`, `ctr: u32`

**Summary.** `Aes128Prng` provides a manual `impl Zeroize` but has **no `Drop` and no
`derive(ZeroizeOnDrop)`**, so the wipe is never auto-triggered. The compiler-synthesised
drop glue delegates only to the `cipher` field. The AES-CTR keystream `data` (a
key-derived secret) and the `ptr`/`ctr` position state therefore persist in the reclaimed
stack frame after the PRNG is dropped. The PRNG is built per-block inside the PRP
(`Aes128Prng::init(key)`, prp.rs:27), so this drop happens frequently during operation.

**Evidence:**

- **[source]** prng.rs:12 — `impl Zeroize for Aes128Prng` exists but there is no `impl Drop` or `derive(ZeroizeOnDrop)`, so the manual zeroize is never called automatically. The manual body (prng.rs:13-17) loops over `self.data` only; `cipher`, `ptr`, and `ctr` are untouched.
- **[mir]** `6f04dcee.mir` — `Aes128Prng::zeroize` loops `self.data` only; no `Drop`/`ZeroizeOnDrop` impl present in MIR; the drop glue delegates only to `cipher` (F-RUST-MIR-0003).
- **[ir]** `6f04dcee.O0.ll:503-514` — `drop_in_place::<Aes128Prng>` GEPs only to byte offset 256 (the `cipher` field) and calls `drop_in_place::<aes::soft::Aes128>`; offsets 0..256 (`data`) and `ptr`/`ctr` are never zeroized on the drop path (F-RUST-IR-0002).
- **[ir]** `6f04dcee.O2.ll:1823` — `data` is `@llvm.memset(..., 0, 256, false)` **non-volatile** at construction only; it is never wiped at drop (F-RUST-IR-0003).
- **[asm]** `6f04dcee.O2.s:1481-1491` — AArch64 corroboration that the key-schedule wipe (`cipher`) survives at O2; no zero-store covers `data`/`ptr`/`ctr` on the drop path (F-RUST-ASM-0001, experimental backend, hand-verified).
- **[poc]** PoC confirmed: secret persists after drop (exit code 0); verification passed — 253/256 keystream bytes survive drop versus 0/256 with a `ZeroizeOnDrop` control.

**Compiler Evidence:**

- Opt levels analyzed: O0, O1, O2
- **O0:** `drop_in_place::<Aes128Prng>` (O0.ll:503-514) drops only `cipher` (GEP offset 256); the `aes` `ZeroizeOnDrop` zeroes the 704-byte fixslice key schedule via `<[u64;88] as Zeroize>::zeroize`. `data`/`ptr`/`ctr` are never touched on drop.
- **O1:** Same drop-path structure as O0; manual `Aes128Prng::zeroize` still has no trigger.
- **O2:** The key-schedule wipe is inlined into a `store volatile i64 0` loop (offset 0..704, step 8) followed by `fence syncscope("singlethread") seq_cst` on **both** the normal **and** the unwind/cleanup paths (O2.ll:1854-1856) and **survives**. The `data` keystream is `memset(0)` only at construction (O2.ll:1823, non-volatile), never at drop.
- **Summary:** The `aes::Aes128` `ZeroizeOnDrop` key-schedule wipe is present at O0 and survives (inlined, volatile, fenced) at O2 on all paths — it is **not** optimized away. The genuine residual leak is `Aes128Prng`'s own `data` keystream + `ptr`/`ctr`, which the synthesised drop glue never zeroizes because there is no `Drop`/`ZeroizeOnDrop` to trigger the manual zeroize.

**PoC Validation:** exploitable (verified)

- Exit code: 0 (0 = secret persists = exploitable; 1 = wiped = not exploitable)
- PoC files: `poc/ZA-0001_missing_source_zeroize.rs` (test), `poc/ZA-0001_missing_source_zeroize_bin.rs` (binary), shared replica `poc/za_0001_replica.rs`
- Compiled and ran at debug (-O0) and release; deterministic.
- Verified: **yes** — all six verification checks passed (target_variable, target_function, technique, optimization_level, exit_code_interpretation, result_plausibility).
- Result: 253/256 keystream bytes survive drop with the verbatim (no-trigger) impl; the `Aes128PrngFixed` control with `ZeroizeOnDrop` yields 0/256, demonstrating both the leak and that the recommended fix closes it.
- Technique: version-pinned byte-for-byte replica (the real type is crate-private), `ManuallyDrop` + `ptr::drop_in_place` to run exactly the synthesised destructor, then `ptr::read_volatile` of the keystream storage — the correct primitive for a Rust `MISSING_SOURCE_ZEROIZE` PoC. Deps pinned to `aes=0.8.2` (zeroize feature) and `zeroize=1.5.7`, matching `ore-rs/Cargo.toml`.

**Recommended Fix:**

Add `#[derive(zeroize::ZeroizeOnDrop)]` to `Aes128Prng` so the manual `Zeroize` impl is
auto-triggered on drop, **and** extend the `zeroize` body to wipe all secret-derived
state, not just `data`:

- keep the existing `data` keystream loop;
- additionally clear the position state, e.g. `self.ptr = (0, 0); self.ctr = 0;`.

Do **not** manually re-wipe `cipher`: the AES key schedule is already zeroized by the
`aes` crate's own `ZeroizeOnDrop` (enabled via `aes = { features = ["zeroize"] }`), so
deriving `ZeroizeOnDrop` on `Aes128Prng` composes cleanly with it. After the change,
confirm at the IR layer that the synthesised drop glue GEPs offset 0..256 and zeroes the
keystream. The PoC's `Aes128PrngFixed` control already demonstrates this fix yields 0/256
surviving bytes.

---

## PoC Validation Results

| Finding | Category | PoC File | Exit Code | Result | Verified | Impact |
|---|---|---|---|---|---|---|
| ZA-0001 | MISSING_SOURCE_ZEROIZE | `poc/ZA-0001_missing_source_zeroize_bin.rs` | 0 | exploitable | Yes | Confirmed — verified exploitable PoC reinforces `confirmed` confidence (253/256 keystream bytes survive drop vs 0/256 control) |

---

## Superseded Findings

Two source-level findings were partially superseded by IR/ASM hard evidence and re-scoped,
then folded into the single retained finding ZA-0001. No finding was silently dropped.

| Superseded | Superseded By | Reason |
|---|---|---|
| F-RUST-SRC-0001 (MISSING_SOURCE_ZEROIZE, high) | F-RUST-IR-0002 (→ ZA-0001) | Source claimed "on drop nothing is wiped." IR/ASM show the synthesised drop glue **does** wipe the AES key schedule (`cipher`) via the `aes` crate's `ZeroizeOnDrop` (volatile loop + fence, surviving O2 on normal and unwind paths). The residual valid part — manual `zeroize` never triggered, `data`/`ptr`/`ctr` not wiped — was retained and re-scoped from high to medium. |
| F-RUST-SRC-0002 (PARTIAL_WIPE, medium) | F-RUST-IR-0002 (→ ZA-0001) | Source claimed `Aes128Prng::zeroize` ignores `cipher`, leaving AES round keys in memory. The manual zeroize does ignore `cipher` (confirmed F-RUST-MIR-0003), but it is never auto-triggered anyway, and the actual drop path wipes the 704-byte key schedule (F-RUST-IR-0002). So "AES round keys remain in memory" is **mitigated** for the drop case. The accurate residual gap is the `data` keystream (F-RUST-IR-0003) + `ptr`/`ctr`. Also corrected: `data` is a stack-inline array, not a heap Vec. |

---

## Confidence Gate Summary

| Finding / ID | Action | Reason |
|---|---|---|
| ZA-0001 | Confirmed (held) | 3+ independent signals agree on the residual gap: [source] manual Zeroize with no trigger, [mir] drop glue delegates only to `cipher`, [ir] `data` never wiped at drop + `drop_in_place` GEPs only `cipher`. ≥2 signals → confirmed. MCP available, so no MCP-unavailable downgrade. A verified exploitable PoC is a strong additional signal (can upgrade likely→confirmed; ZA-0001 was already confirmed). Severity set to medium because the primary key schedule **is** protected; residual exposure is the key-derived CTR keystream + counters (lower impact than raw key leakage). |
| F-RUST-IR-0001 (OPTIMIZED_AWAY_ZEROIZE, high) | Refuted — dropped from active findings | Automated false positive. `OPTIMIZED_AWAY_ZEROIZE` requires IR-diff evidence that a wipe was removed. Here the per-symbol volatile-store drop in the standalone `write_volatile::<u64>` helper is an **inlining artifact**: crate-wide `store volatile` count **rises** O0→O2 (2 → 138). No wipe was eliminated. Recorded in the refuted bucket for the audit trail. **No OPTIMIZED_AWAY_ZEROIZE finding is emitted in this run.** |
| F-RUST-MIR-0001 / F-RUST-MIR-0002 (hash_key) | Refuted — dropped from active findings | `hash_key` is `&GenericArray<u8,U16>`, a borrow of caller-owned `b_right`, not an owned secret. No owned sensitive local leaks on unwind/Err paths. |
| F-RUST-ASM-0001 (info) | Corroborating-only — not emitted as a finding | Positive machine-level corroboration of F-RUST-IR-0002: the AArch64 checker returned 0 STACK_RETENTION / REGISTER_SPILL findings and the key-schedule volatile wipe survives to O2 machine code. This is evidence the key schedule **is** wiped, not a leak. (Experimental AArch64 backend; hand-verified.) No `STACK_RETENTION`/`REGISTER_SPILL` finding is created because no asm evidence of a non-wiped secret exists. |

No rationalization-override attempts were made or rejected during this run.

---

## Analysis Coverage

| Metric | Value |
|---|---|
| TUs in scope | 1 (`packages/ore-rs/src/lib.rs`, hash `6f04dcee`, lib `ore-rs`) |
| TUs analyzed | 1 / 1 |
| TUs with sensitive objects | 1 |
| Module files scanned | 15 |
| Agent 1 (MCP/preflight resolver) | success — serena MCP available; nightly 1.95.0, uv 0.8.17; MIR/IR/ASM emit all passed |
| Agent 2b (Rust source analyzer) | success (with tool limitation — see below) — 6 sensitive objects, 2 source findings |
| Agent 3b (Rust compiler analyzer) | success — MIR + IR (O0/O1/O2) + ASM (O2) analyzed |
| Agent 4 (report assembler) | success (interim + final) |
| Agent 5 (PoC generator) | success — 1 PoC generated, compiled, validated, and verified |
| Agent 6 (test generator) | skipped — runtime tests disabled in config |

**Features and impact:**

- **Semantic IR analysis:** disabled (preflight `enable_semantic_ir=false`). No loop-unrolling / phi-node / SSA findings were produced; not required for this finding, which is grounded in drop-glue structure.
- **CFG analysis:** disabled (preflight `enable_cfg=false`). No dominator / all-paths findings. The unwind-path coverage that would normally come from CFG was instead established directly from the O2 IR (volatile wipe present on both normal and unwind paths).
- **Runtime tests:** disabled. PoC-based runtime validation was performed instead and is sufficient to confirm the finding.
- **Assembly analysis:** enabled on an **experimental AArch64 backend**; used only as positive corroboration (F-RUST-ASM-0001) and flagged for manual re-check.

**Tooling incompatibility encountered during the run (actionable):**

`semantic_audit.py` is **incompatible with rustdoc `format_version: 57`**. The current
nightly rustdoc JSON nests the item `kind` under `inner.{struct,enum}` instead of a
top-level `item['kind']`, and expands `#[derive(...)]` into the impls list rather than
emitting raw `attrs` strings. The shipped script reads the legacy layout, so it silently
**skipped all 14 structs/enums and produced 0 raw findings**. The two source findings
(F-RUST-SRC-0001/0002) and the 6 sensitive objects were recovered by a manual,
trait-aware pass over the same JSON. Recommended fix to the tool: (1) derive `kind` from
`inner` keys; (2) read derived traits from `impl.trait.path` in the impls list. This did
not reduce coverage for this run, but would cause silent under-reporting on future runs if
left unfixed.

---

## Appendix: Evidence Files

Paths are relative to the run working directory `/tmp/zeroize-audit-c212f1cdd302/`.

| Finding | Evidence File | Description |
|---|---|---|
| ZA-0001 | `source-analysis/source-findings.json` | Source findings F-RUST-SRC-0001/0002 (re-scoped → ZA-0001) |
| ZA-0001 | `source-analysis/rust-semantic-findings.json` | Manual trait-aware semantic findings (format v57 fallback) |
| ZA-0001 | `source-analysis/sensitive-objects.json` | SO-5001..SO-5006 inventory (subject = SO-5005) |
| ZA-0001 | `rust-compiler-analysis/mir-findings.json` | MIR finding F-RUST-MIR-0003 (drop glue delegates only to cipher) |
| ZA-0001 | `rust-compiler-analysis/ir-findings.json` | IR findings F-RUST-IR-0001 (refuted), -0002, -0003 |
| ZA-0001 | `rust-compiler-analysis/asm-findings.json` | ASM corroboration F-RUST-ASM-0001 (AArch64, experimental) |
| ZA-0001 | `rust-compiler-analysis/superseded-findings.json` | Supersession records for F-RUST-SRC-0001/0002 |
| ZA-0001 | `rust-compiler-analysis/6f04dcee.mir` | MIR dump |
| ZA-0001 | `rust-compiler-analysis/6f04dcee.O0.ll` | LLVM IR at O0 (drop_in_place lines 503-514, 6643-6651) |
| ZA-0001 | `rust-compiler-analysis/6f04dcee.O1.ll` | LLVM IR at O1 |
| ZA-0001 | `rust-compiler-analysis/6f04dcee.O2.ll` | LLVM IR at O2 (data memset:1823; key-schedule volatile wipe + fence:1854-1856) |
| ZA-0001 | `rust-compiler-analysis/6f04dcee.O2.s` | AArch64 assembly at O2 (volatile zero-store loop:1481-1491) |
| ZA-0001 | `poc/ZA-0001_missing_source_zeroize.rs` | PoC test (vulnerable + control-fix) |
| ZA-0001 | `poc/ZA-0001_missing_source_zeroize_bin.rs` | PoC binary (exit 0 = exploitable) |
| ZA-0001 | `poc/za_0001_replica.rs` | Version-pinned byte-for-byte Aes128Prng replica |
| ZA-0001 | `poc/poc_validation_results.json` | Compile + run results |
| ZA-0001 | `poc/poc_verification.json` | Semantic verification (6/6 checks passed) |
| ZA-0001 | `poc/poc_final_results.json` | Merged validation + verification (input to this report) |
| run | `report/raw-findings.json` | All 9 findings pre-gating, original namespaced IDs |
| run | `report/id-mapping.json` | Namespaced → ZA mapping + refuted/superseded/corroborating buckets |
| run | `report/findings.json` | Final gated structured output (matches schemas/output.json) |
| run | `report/notes.md` | Assembly process notes |
| run | `preflight.json` | Run configuration and preflight checks |
