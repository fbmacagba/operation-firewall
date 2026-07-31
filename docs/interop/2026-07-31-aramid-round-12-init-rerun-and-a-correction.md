# Round 12 — `aramid init` re-run here, one correction, one bug it exposed

Written by aramid. Short housekeeping round.

## Why init was re-run

Round 10 and 11 changed aramid's behaviour, but your `ARAMID.md` is a
generated, aramid-owned file (`<!-- aramid:managed -->`) and still carried the
text generated on 2026-07-30. Concretely, it still told a reader this:

> Because the underlying merge replaces the list rather than adding to it, an
> incomplete list (or an empty one) silently drops every OTHER packaged
> BLOCK-tier rule for that tool too. aramid prints a stderr notice naming
> exactly which rule ids were **dropped**.

That is precisely the hole your point 6 identified, and it has been closed
since `a71356f` — nothing is dropped any more, it is restored. Your own
onboarding doc was still advertising the vulnerability as open. That is worse
than a stale comment, so `aramid init` was run here to regenerate it.

## What it actually changed: one file

Verified by md5 before and after:

| Path | Result |
|---|---|
| `ARAMID.md` | **regenerated** — block_rules section corrected; header now `python, rust` / `cargo` |
| `aramid.toml` | unchanged — `left untouched` |
| `.githooks/pre-commit` | unchanged (identical md5) |
| `.githooks/pre-push` | unchanged (identical md5) |
| `.gitignore` | unchanged (identical md5) |
| findings baseline | `baseline already exists -- left untouched` |

Your `[tests].command`, `semgrep_block_armed = false` and `bake_started` are
all intact. No re-baselining, no re-scan of history findings, no hook
rewrites.

## Correction to round 10

Round 10 said the stale `aramid.toml` header comment (`detected stack:
python; package manager: none`) would be refreshed by `aramid init`. **That
was wrong**, and it is the kind of wrong that wastes someone's time: init's
idempotency contract is explicit that `aramid.toml` is "written ONLY if
absent -- a second `init` never touches a user-edited stub", and it prints
`left untouched`. Running init does not refresh that comment and never will.

The good half of the same fact is that your config is safe from any future
re-init. The comment is cosmetic and can be hand-edited or ignored; round 10
has been annotated in place rather than rewritten.

## A bug your repo exposed

Running init here printed:

```
aramid: init: WARNING -- ...\.githooks\post-commit missing or not
aramid-managed after install; hooks may not be armed
  hooks armed:       NO -- see warning above
```

That was **false**, and aramid contradicted itself to produce it. Three lines
earlier `install()` had correctly refused to clobber graphite's `post-commit`
trampoline, relocated aramid's own shim to `post-commit.local`, and said "not
stale, nothing to resolve". Then `_validate_hook_shim` checked only whether
the canonical slot carried aramid's marker — which a foreign-managed slot
never does — and declared the repo unarmed. Your gates were armed the whole
time; your ledger shows pre-commit running on every commit today.

This mattered beyond cosmetics: any repo where another managing tool owns a
hook slot would report `hooks armed: NO`, and the obvious operator "fix" is
to clobber the other tool's hook — breaking the coexistence `install()` was
carefully written to preserve.

Fixed in aramid: the check now accepts a foreign-managed slot when aramid's
own shim demonstrably survives relocated beside it, reusing
`hooks._find_chained_aramid_shim`, which already recognised such relocations
generically. Both halves are still required, so a foreign trampoline with no
surviving shim — and a missing slot even when a relocated sibling exists —
still report a genuine gap. Re-run against this repo after the fix:

```
  hooks armed:       yes
```

Found only because init was run against a real repo with a real second
managing tool in it. That is now three defects this week that a green test
suite did not catch and contact with your repository did.

## Note

`ARAMID.md` is modified in your working tree and left uncommitted, alongside
your in-flight Milestone 1 work. Committing it is yours to do — this round
only explains why it changed.
