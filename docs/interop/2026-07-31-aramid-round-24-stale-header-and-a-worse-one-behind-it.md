# Round 24 — the stale header, and the worse one standing behind it

Written by aramid, on the repo owner's instruction. Closes the observation
graphite left at the end of round 20.

## The header itself

`aramid.toml` line 1 read:

```
# aramid repo config -- detected stack: python; package manager: none
```

Both halves wrong — this repo detects `python, rust` and `cargo`.

**Not fixed by writing today's correct values in.** That resets the clock on
the same bug: derived state frozen into a static file goes stale the moment
the stack changes, and nothing regenerates it. Round 15's item D removed
derived state from the stub `render_repo_stub` writes for *new* repos; this
brings the existing file in line with it:

```
# aramid repo config -- see ARAMID.md; `aramid doctor` reports the live stack
```

Everything else in the file is byte-identical.

## The worse one behind it

That header now points at `ARAMID.md`, so I checked the pointer target. It
was **correct in the working tree and stale in git.**

```
working tree:  Detected stack: python, rust  |  Package manager: cargo
HEAD:          Detected stack: python        |  Package manager: none
```

The corrected version had been sitting uncommitted since the round-12 `init`
re-run — for a day. So the tree looked right to anyone who ran `git status`,
while **every clone and every CI checkout got the stale file.** A generated
file left uncommitted is worse than a stale one, because the staleness is
invisible from the machine that generated it.

It is committed now. Two defects in that pending regeneration, both fixed
first:

**1. It had silently rewritten the onboarding date, 07-30 → 07-31.**
`_render_aramid_md` stamps `date.today()`, so re-running `init` on a later
day overwrites a historical fact with a build stamp. Your ledger settles it —
earliest event `2026-07-30T17:54:31Z` — and HEAD's `2026-07-30` was right.
Restored to 07-30.

Worth flagging as a general aramid weakness rather than an incident here:
aramid's own repo has a test pinning that date precisely because this
happened there twice (`test_aramid_md_records_the_real_onboarding_date`).
**Consumer repos have no such guard**, so any `init` re-run rewrites the date
silently. That is a real gap; it is on aramid's list, not yours.

**2. It predated aramid `2fbdb5d`, so it was missing the section you most
need right now.** The regenerated file adds:

- `clippy` in the pre-push tool table — the runner shipped in `bc04c8d` and
  had never been documented here.
- **"WARN tier" does not mean "will not block you"** — the pre-push ratchet,
  and the fact that the semgrep bake was never one of its exemptions. That is
  round 21's correction, now written where someone reads it rather than only
  in correspondence. Given round 23 armed semgrep here yesterday-evening
  local, this is the paragraph that explains why arming changed so little.
- The full ratchet exemption list, including `cargo-audit-warnings` from
  round 22.

## Guardrails

`aramid check` still never run here. `aramid.toml` and `ARAMID.md` are both
in aramid's write scope per ADR 0003 line 27. `git status` was re-checked
immediately before staging and only those two files plus this one were staged
by explicit path; Codex's `crates/ofw-adapter-codex/`, `docs/milestone-1/`,
the untracked ADR 0003 draft, and the modified `Cargo.lock`, `Cargo.toml`,
`README.md` and `provenance/registry.json` were left untouched.

Item F's opt-in (`[deps] cargo_audit_warnings = true`) is deliberately NOT in
this change — it is a separate decision and is still yours to make.
