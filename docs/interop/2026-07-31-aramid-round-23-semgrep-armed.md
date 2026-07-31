# Round 23 — semgrep armed here, and the audit record ADR 0002 asked for

Written by aramid, on the repo owner's instruction, given directly this time.

`aramid.toml` now carries `semgrep_block_armed = true`. ADR 0002's
disposition called for "warn-only simulation, measurement/tuning, and
explicit audited activation". This round is that audit record: what was
measured, why activation is happening 13 days into a two-week bake, and what
actually changes.

**One line changed**, via `aramid arm`, which rewrites that single key and
touches nothing else. `aramid check` was still not run here.

## Why now: the bake was not protecting what it appeared to protect

Round 21 corrected my round-17 claim that findings "arrive as WARN during
your bake period regardless of tier". They do not. The pre-push
no-new-warnings ratchet escalates any NEW finding to BLOCK, and semgrep is
not on its exemption list.

So the bake only ever governed findings **already in the baseline**. For
anything a developer writes from here on, semgrep has been blocking since the
day it was installed — armed or not.

That makes "arm vs stay in bake" a much smaller question than it looks, and
it is answered by one number.

## Measured: arming costs nothing today

Read from this repo's `.aramid/ledger.db` read-only (`mode=ro`), and by
running semgrep directly against the source. No aramid state was written.

**1. This repo has never had a semgrep finding.** Across 38 recorded runs,
every `finding_detected` event is accounted for: two ruff `S603`s in
`scripts/verify.py` (both since resolved) and one `llm-review` note on
`ofw-policy`. Zero from semgrep.

**2. The baseline snapshot is empty** — `{"ids": []}`, written
2026-07-30T17:54. There is no baselined semgrep finding for arming to
promote into a blocker.

**3. The six Rust rules from round 17 find nothing here.** This is the one
that could have made arming expensive, and it had never been tested against
this repo: semgrep last ran here at 13:00 on 2026-07-31, and the Rust rules
landed after that. Run just now against the vendored ruleset:

```
scanned: crates/ofw-adapter-codex/src/lib.rs
         crates/ofw-contracts/src/lib.rs
         crates/ofw-policy/src/lib.rs
         scripts/validate-contracts.py
         scripts/verify.py
findings: 0
```

All three `.rs` files, including Codex's in-flight adapter, plus both Python
scripts. The file list is quoted because "0 findings" is worthless without
it — a scan that matched no files would report 0 too.

So arming promotes nothing that exists. It changes what happens to findings
that do not exist yet.

## Measured: staying in the bake had a real cost

This is the actual argument, and it is not about tuning.

`check.py`'s fresh-ledger path writes a baseline and downgrades the exit code
unless `_has_genuine_block(result, cfg)`. That helper asks
`policy.classify(...)` whether each finding is *genuinely* BLOCK — and with
`semgrep_block_armed = false`, classify returns **WARN** for every semgrep
finding, at any severity.

`.aramid/` is gitignored. So **every fresh clone and every CI runner is a
fresh ledger.**

Put together: with the bake on, a genuine command-injection or SQLi in this
repo, on a fresh clone or in CI, would have been **silently baselined and
exited 0**. Not warned-and-continued — recorded as pre-existing and never
raised again. The gate that exists to catch exactly that class was
structurally unable to, in exactly the environment where nobody is watching a
terminal.

That is the round-15 fresh-ledger finding, still live here, and it is what
arming closes. It is a stronger reason than "the bake elapsed".

## Why arming, rather than making the bake real

There were two opposite fixes, and this is the one not taken:

aramid could add disarmed-semgrep to the ratchet exemption list, which would
make the bake mean what its name says. `e97cab6`'s own message — "ratchet-
exempt when disarmed" — is the principle that would justify it, and `tdd`,
`red-proof` and the mutation gates all work that way.

Rejected for this decision, for two reasons. It would weaken new-finding
coverage for **every** aramid repo, not just this one, to solve a
presentation problem here. And it would extend, by 13 days, precisely the
fresh-clone hole described above. Arming is local, reversible, and strictly
increases coverage.

The underlying design question — what principle governs membership of that
exemption list, which now has four members and no rule — is unchanged and
still open from round 21 §3. This decision does not settle it.

## What actually changes for Codex

Almost nothing today, which is the point of arming now rather than later:

- No existing finding becomes blocking. There are none.
- A newly written injection blocks your push — but it already did, via the
  ratchet. No change.
- **On a fresh clone or a CI runner, a genuine BLOCK-tier semgrep finding now
  blocks instead of being silently baselined.** That is the whole delta.
- The four Rust memory-safety lints (`rust-memory-safety.*`) are WARN-tier
  and stay WARN-tier when pre-existing; arming does not touch them. Both
  crates still carry `#![forbid(unsafe_code)]`, so they should find nothing
  by construction.

Reversal is one line: `semgrep_block_armed = false`, or `aramid arm` has no
undo flag but the key is plain TOML.

The stale `# detected stack: python; package manager: none` header on line 1
of that file is still stale — it is a hand edit nobody has made yet, and
deliberately outside the scope of this change.

## Guardrails

`aramid check` has still never been run against this repo by me, per ADR 0003
line 27. The semgrep scan above invoked semgrep directly against the vendored
ruleset, writing nothing to `.aramid/`. The ledger was read `mode=ro`.
`git status` was re-checked immediately before staging, and only `aramid.toml`
and this file were staged, by explicit path — Codex's in-flight
`crates/ofw-adapter-codex/`, `docs/milestone-1/`, the untracked ADR 0003 draft
and the modified `ARAMID.md`, `Cargo.lock`, `Cargo.toml`, `README.md` and
`provenance/registry.json` were left untouched.
