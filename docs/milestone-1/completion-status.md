# Milestone 1 completion status

Assessed 2026-08-07 against the eight completion criteria in
[the Milestone 1 completion design](../superpowers/specs/2026-08-01-milestone-1-completion-design.md#completion-criteria).

## The claim that is not available

Before the criteria, the constraint that governs them. The approved design
excludes **"production active-enforcement claims"** from Milestone 1 scope, and
states that Milestone 1 artifacts

> are development artifacts, not production enforcement releases. Signing and
> verification mechanisms are exercised before Milestone 2 but no
> active-protection claim is permitted.

So "production ready" is not a state Milestone 1 can reach by definition, and no
amount of work inside Milestone 1 makes it reachable. It requires Milestone 2:
bound approvals, replay protection, pre-execution revalidation, and a verified
live host integration. This document therefore reports how much of the
prerequisite is done, not whether the claim can be made — it cannot.

## Criteria

| # | Criterion | Status |
| --- | --- | --- |
| 1 | Executable passing evidence for every included functional requirement | **Partial** |
| 2 | Every unsupported or incomplete recognized mutation is `indeterminate` and the hook denies | **Met** |
| 3 | Windows, Linux, macOS resolver matrices pass without assuming platform defaults | **Partial** |
| 4 | Red-first, negative, abuse, property, fuzz, mutation, concurrency, deadline and performance gates pass | **Partial** |
| 5 | No audit/debug/error fixture leaks canary secrets or raw sensitive payloads | **Met** |
| 6 | The `NoRestriction` advisory is resolved by executable baseline-proof enforcement | **Met** |
| 7 | Dependency, SBOM, reproducibility, compatibility, rollback and clean-room provenance evidence is current | **Partial** |
| 8 | README and diagnostics state that approvals, replay protection, revalidation and production enforcement remain Milestone 2 | **Met** |

### 1 — Functional evidence: partial

Implemented with tests: typed contracts and strict v1 deserialization, monotonic
policy evaluation, policy bundle loading and atomic activation, bounded Codex
envelope parsing, Bash/apply_patch payload extraction, read-only Git intent
interpretation, repository- and path-scoped target resolution, the built-in
baseline and final composition, structurally redacted audit construction, and
the CLI.

Audit persistence landed on 2026-08-07: records append under an exclusive lock,
segments rotate by atomic same-directory rename, and a damaged trailing record
is quarantined on recovery with health reported degraded. The sink refuses an
audit directory inside the repository it audits. **Retention is deliberately
not implemented** — deleting closed segments is the one operation here that
cannot be reviewed afterwards, and the cost of getting it wrong is unbounded
against a cost of disk usage for not having it.

Two defects in the decision core were found and fixed on 2026-08-07, both
latent rather than exploitable, and both of a kind that only becomes live with
the *next* grammar slice:

- The built-in baseline's read allow row required an absent execution surface;
  the create/update row did not. A bounded, reversible, repository-local edit
  therefore derived `Allow` even through a command that reaches an execution
  surface. Unreachable today only because the interpreted subset has no
  `Create` or `Update` kind — apply-patch is the next slice and is both. The
  condition is now hoisted into the shared "may be allowed at all" guard so a
  row added later cannot omit it.
- `effect`, `privilege` and `publication` were literals at the intent-to-
  evidence boundary, so every recognized operation was a standard-privilege,
  non-publishing read by construction. A `git push` added to the old match arm
  would have been classified a read and skipped the baseline's publication deny
  row, with nothing in the diff to show a security decision had been made. They
  are now per-subcommand entries in the grammar table, and `ofw-core` reads
  them through exhaustive matches.

Path-operand resolution landed on 2026-08-07 for `git log` and `git diff`, the
first interpreted subcommands taking operands and the first resolution scoped
to specific paths. An explicit `--` separator is required, because git's
operand syntax is ambiguous between a revision and a path and git resolves it
by consulting the ref store and working tree — neither of which this project
may do. `git log src/main.rs` is therefore refused rather than guessed at.
Resolution is all-or-nothing: one operand that does not canonicalize fails the
whole operation. Verified against the built binary, not only in tests —
`git log -- present.txt` asks, the same command pointed through `../..` at a
file outside the boundary denies, and an alternate-data-stream spelling is
refused. `GRAMMAR_REVISION` moved to 1.1.0.

Not implemented: retention, revision operands (so `git show`, and `git log`
against a revision, stay out of the subset), the apply-patch grammar, the
PowerShell subset, the revalidation fingerprint, ownership/permission
verification of the audit directory (per-platform, and the Windows path needs
`unsafe`), and a trusted-configuration file loader. `ofw doctor` reports each
of these rather than implying coverage.

### 2 — Unsupported and incomplete operations deny: met

Every path converges on deny, and each stage reports how far it got:
`COMMAND_NOT_LITERAL`, `OPERATION_INTERPRETATION_UNSUPPORTED`,
`TRUSTED_CONFIGURATION_MISSING`, `TARGET_RESOLUTION_INDETERMINATE`,
`POLICY_BUNDLE_INVALID`, `AUDIT_UNAVAILABLE_FOR_MUTATION`. The hook emits exit 2
with empty stdout in every case, and `doctor` probes the installed command path
to confirm it.

### 3 — Resolver matrices: partial

The resolver is one portable implementation over `std::fs::canonicalize`, which
does call the platform's native API and does resolve symlinks and junctions. It
is **not** the per-platform matrix the design requires: reparse-point,
mount/volume identity, alternate-data-stream, per-directory case-sensitivity and
Unicode-normalization evidence are not collected.

Nothing assumes a platform default — anything that cannot be established is an
error and an error is `indeterminate` — and CI runs the suite on all three
platforms. But "passes on three platforms" is weaker than "declares and tests a
support matrix per platform", and the gap is a `forbid(unsafe_code)` question as
much as an effort one: Windows reparse and volume evidence needs platform
bindings, which would need `unsafe` in this project's own crates.

### 4 — Test gates: partial

Present: **139 tests; 23 retained red-first witnesses**; negative and abuse
corpora; canary tests on the CLI streams, bundle errors and audit records;
property-style monotonicity; deadline handling in the hook.

Both figures are counted from a run of `scripts/verify.py` immediately before
writing them, never carried forward. Earlier the same day this section claimed
"120 tests; 23 witnesses" while a session handoff note claimed "139 tests; 24
witnesses", and the true figure at that moment was **131 and 23** — two
inherited counts, wrong in opposite directions, neither checked before being
repeated. That the total has since genuinely reached 139 is a coincidence and
not a vindication of the note. A stale count in a document whose whole purpose
is honest reporting is a defect in the document.

The decision space is now covered exhaustively rather than by sampled cases:
three baselines plus the no-proof case against all four policy outcomes,
sixteen cells, asserting that `Allow` is reachable from exactly one of them.
Weakening `decide` so an indeterminate policy no longer short-circuits reds
that test and no other, which is why it was written.

Fuzzing is present as of 2026-08-07: `fuzz/` holds libFuzzer targets for all
three untrusted parsers (Codex envelope, policy bundle, shell tokenizer), run by
a nightly-only CI job. Nightly is scoped to that job alone — `fuzz/` is excluded
from the workspace so the 1.97.1 pin, which is a reproducibility property of the
shipped artifact, is not weakened to enable it. Seeds are committed to
`tests/fuzz-corpus/` and replayed by the **stable** suite, so a crash found once
stays checked on every ordinary `cargo test` without nightly being installed.

Concurrency is covered as of 2026-08-07: eight threads appending twelve records
each through the real filesystem lock, asserting that every record survives,
every line parses independently, and none is lost or duplicated. Counting lines
alone would not catch an interleaved write, so the assertion is on parseability
and identity too.

Absent: mutation testing, and warm-path performance benchmarks against the
design's p95 ≤ 25 ms target.

Every guard added in this milestone was verified load-bearing by weakening it
alone and confirming the matching test reds — not merely by the suite passing.

### 5 — No canary leaks: met

Redaction is structural rather than a scrubbing pass: `AuditEvent` has no field
that can hold a payload. Every field is a compiled-in literal, a SHA-256 digest,
a bounded operator-authored identifier, or a number. CLI reasons are all
`&'static str`. Bundle errors carry no policy content, because `serde_json`'s
own messages quote the input and only the classification crosses the boundary.
Each is canary-tested across `Display`, `Debug` and serialized form.

### 6 — The `NoRestriction` advisory: met

Policy silence cannot reach an allow: allow requires a proof whose derived
baseline is allow, and an absent proof is always `indeterminate`. This is now
established exhaustively rather than by example — see criterion 4.

The advisory exists as an open finding in the `aramid` ledger
(`b79b75cd…`, `llm/logic` on `crates/ofw-policy/src/lib.rs`). Its prescribed
fix — "represent built-in supported-operation proof as an explicit input, and
return `Indeterminate` unless that baseline proves the operation is supported"
— **is present**: that is exactly `ofw_core::decide`'s signature and its
absent-proof branch.

The finding's stated concern had a second half — "**if a caller later maps
`NoRestriction` to allow**" — and that half is not structurally prevented:
`EffectivePolicy::evaluate` is public, so a caller can read the outcome and
compose its own answer without calling `decide`.

**The required review happened on 2026-08-07 and accepted that residual.** The
reasoning: no library API can prevent it. A caller who ignores the composition
function is writing a different decision engine, not bypassing a guard, and an
API contorted to make that unexpressible would buy nothing a reader of `decide`
does not already get. The finding is closed in the ledger via
`aramid override`, carrying this reasoning, so the decision is auditable rather
than implicit in the finding's disappearance.

What the review relied on, all first-hand: `decide` takes the proof as an
explicit argument and returns `Indeterminate` when it is absent; the sixteen-cell
table asserts `Allow` is reachable from exactly one combination; and weakening
`decide` so an indeterminate policy no longer short-circuits reds that test and
no other.

### 7 — Supply-chain and provenance evidence: partial

Done: [ADR 0004](../decisions/0004-vetted-serialization-and-digest-dependencies.md)
records the mandated pre-download review; CI runs `cargo audit --deny warnings`,
fails closed on any licence outside a reviewed allowlist, and generates a
CycloneDX SBOM that is a pure function of `Cargo.lock` — regenerated twice and
diffed, so it is usable as evidence of what shipped.

Partly done: **rebuild determinism**. CI builds the release binary twice and
requires identical SHA-256, and publishes the digest alongside the SBOM. This
catches a build embedding a timestamp, a random seed, or run-varying iteration
order. Measured locally first rather than assumed — two Windows release builds
of `ofw.exe` produced identical digests.

Not done: **full reproducibility**, which is the stronger claim people hear.
That needs identical bytes from a different absolute path and a different
machine, requiring `--remap-path-prefix` and a controlled build environment.
The CI step is named for what it checks rather than for the property it
approximates, so a green run cannot be mistaken for the stronger claim.

Also not done: rollback evidence and the compatibility matrix, which are
documented as design intent but not exercised.

### 8 — Honest README and diagnostics: met

The README's status banner states the design's own prohibition rather than
reading as modesty. `ofw doctor` reports `enforcement: not_active`,
`audit_health: unhealthy`, per-component status, trusted-configuration
provenance limits, policy scope-filtering limits, and why `hook_registration`
stays `unconfirmed`. It was corrected twice this cycle — once for understating
what shipped, once for overstating what was usable — and both directions are
now covered by tests.

## Open items that need a decision rather than effort

All were decided on 2026-08-07:

- **Fuzzing**: nightly added for the fuzz job only; the workspace pin is
  untouched. Done.
- **The Codex wire**: confirmed by read-only inspection of the installed
  binary's embedded JSON Schema, with explicit authorisation. The allow object
  this project emits is correct. It also **corrected** a claim in this project's
  own research — `ask` *is* a valid wire decision, so the current
  `ask` → wire-deny mapping is a design choice rather than the protocol
  constraint it was recorded as. The follow-on decision that surfaced was then
  taken: **the mapping stays**, now as a choice. Deny is strictly more
  restrictive than ask, so it cannot admit anything asking would have blocked;
  `git status` settles at `ask`, making this the common path rather than an edge
  case; and there is no live host integration yet against which to test the
  alternative. Revisit when there is.
- **Per-platform resolver evidence**: the workspace-wide `forbid(unsafe_code)`
  is kept, and the evidence stays uncollected. Criterion 3 remains partial by
  choice rather than by omission, and this is the reason.
- **The `NoRestriction` advisory** (criterion 6): reviewed and closed, with the
  residual accepted and the reasoning recorded in the ledger. See criterion 6.
