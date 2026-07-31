# Round 16 — Rust gate discovery: clippy runner, and a correction to round 11

Written by aramid. Code: aramid `bc04c8d` (full unit+integration suite:
1291 passed, 4 skipped).

## The correction first

Round 11 marked Codex's point 1 **Fixed**. That was overstated. The point read:

> Stack detection classified this Cargo workspace as python with "package
> manager: none." That is inaccurate for the repository and means Aramid does
> not natively provide Rust dependency auditing **or Rust-specific gate
> discovery**.

`37a9bd6` closed the dependency-auditing half. The gate-discovery half — any
actual analysis of Rust code — was left untouched and marked done anyway.

What that meant concretely, measured rather than asserted: aramid's language
runners were ruff (Python), eslint (JS/TS) and typecheck (tsc/mypy). Its
vendored semgrep ruleset, `src/aramid/rules/owasp.yml`, is 13 rules:

```
5   languages: [javascript, typescript]
8   languages: [python]
```

**Zero Rust rules.** So semgrep scanned this repo's Rust and could never match
anything — independent of `semgrep_block_armed = false`; arming it would have
changed nothing. On Rust code specifically, aramid contributed gitleaks
(secrets), cargo-audit (dependency CVEs), and the `tests` gate. That is a
secrets scanner and a dependency auditor, not code analysis.

Clippy did run here — but only because you wired it into `scripts/verify.py`
yourself, where aramid sees it as one pass/fail bit from the `tests` runner.
No fingerprint, no severity tier, no triage, no baseline, no regression-pack
entry. A compensating control you built, credited to a gate that did not
provide it.

## What changed

A clippy runner, on the same footing as ruff and eslint.

- Applicability mirrors the others exactly: `"rust" in ctx.stacks`.
- Runs at **pre-push**, not pre-commit — it compiles, so it cannot live in a
  5s budget. 240s timeout; a cold-cache crate that overruns degrades to
  TIMEOUT, which is honest and non-blocking since clippy is not in
  `BLOCK_TIER_KEYS`.
- Both rustc lints (`unused_variables`) and clippy lints
  (`clippy::needless_range_loop`) are reported, with the namespacing
  preserved so `block_rules.clippy` can promote either to BLOCK.
- WARN tier by default. Promotion is an operator decision, and under the
  round-11 floor a repo can only ever ADD to it.

Verified live on a throwaway Rust crate, `aramid check --gate pre-push`:

```
NEW findings (2):
  clippy:unused_variables            src/main.rs:7  unused variable: `unused`
  clippy:clippy::needless_range_loop src/main.rs:4  the loop variable `i` is only used to index `v`

recorded: severity=medium verdict=warn   (both)
tools ran: ['cargo-audit', 'clippy', 'gitleaks', 'semgrep']
```

Each is now a real Finding with a fingerprint and a ledger entry — triageable,
baselineable, suppressible, promotable. That is the difference from a pass/fail
bit.

`aramid doctor` also probes clippy now, conditional on `Cargo.toml`, alongside
the cargo-audit probe added for graphite's item B:

```
MISSING  clippy  not installed -- Rust lint is NOT being checked on this repo;
                 `rustup component add clippy` to enable
                 (non-blocking: clippy is not a BLOCK-tier gate)
```

## Two things checked rather than assumed

Both were candidates for exactly the "reports success, enforces nothing"
failure this thread keeps finding.

1. **Cached runs still report.** If `cargo clippy` emitted nothing on a warm
   build, a second gate run would read as clean. Measured: identical
   diagnostic counts on an unchanged re-run — cargo replays stored
   diagnostics. No false clean.
2. **Exit 101 is ambiguous.** `cargo clippy` exits 101 both when the crate
   fails to compile *and* when the clippy component is not installed —
   opposite meanings. The component is therefore probed by binary
   (`cargo-clippy`) before cargo is invoked, the same lesson as `6efed44`.
   Compile failures are accepted as valid reports, because a failing compile
   emits real `level: "error"` diagnostics that are the most severe output
   clippy ever produces.

## One bug the live run caught that the tests did not

`run_subprocess` names a result after `argv[0]`, which here is `cargo`. My
NDJSON validator returned the result unchanged on the happy path, so the
pipeline recorded the runner as **`cargo`** — a name absent from
`RUNNER_TOOL_NAMES` and different from the `clippy` stamped on every Finding.

The unit tests could not catch it: their fakes returned a result already named
`clippy`, so the real naming path was never exercised. Fixed, and the fakes now
return `"cargo"` as the real `run_subprocess` would, with an explicit assertion
on the restamping.

Fourth defect this week found by running the thing rather than testing it, and
the third of the same shape.

## Still not closed

Honest remaining gap: **semgrep still has no Rust rules.** clippy is a
correctness and style linter, not a security scanner — there is no
bandit-equivalent ruleset for Rust the way ruff's S-rules serve Python. So
Rust security analysis specifically is still thinner than the Python and JS
equivalents. Writing curated Rust security rules is real work and is not done.

Point 1 is now genuinely closed for *gate discovery*; the security-rule depth
behind it is not, and I would rather say so than mark it Fixed twice.
