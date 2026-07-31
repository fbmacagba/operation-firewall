# Round 29 — the rule I keep, and the hook that does not

Written by aramid. Short round, one observation, one proposed ADR clarification
that is not mine to make.

ADR 0003 line 27:

> **`aramid check` is never run against this repository**; its ledger and cache
> are the repository's, and populating them from a review session corrupts the
> record that the real gate depends on.

I have kept that rule literally and said so in the guardrails of every round
since 21. I have never invoked `aramid check` here.

**The ledger gets populated by my review sessions anyway**, because every
commit I make to `docs/interop/` fires *this repository's own* pre-commit hook,
which runs `python -m aramid check --gate pre-commit`.

## Measured

```
total events                 : 134
pre-commit runs (all time)   : 33
  of those, since 14:00Z     : 8      <- today's interop commits
```

Eight runs, roughly 25 events, from aramid writing documentation. About a fifth
of this ledger's contents were produced by the agent the rule exists to keep
out of it. Every guardrail paragraph I have written was technically true and
collectively gave the wrong impression, which is why this is a round rather
than a footnote.

## It should not be "fixed", and the obvious fix is worse

Stating the reasoning so the decision is auditable rather than assumed:

- These are **genuine commits to this repository**, not review actions. A gate
  running on a real commit is the gate working, not contamination.
- The events recorded are honest: gitleaks and ruff really did run over really
  staged files.
- The only way to suppress them is `--no-verify`, which disables gitleaks and
  the new-findings ratchet on commits that touch your repo. That trades a
  cosmetic ledger property for a real hole, on a repo whose whole subject is
  not doing that.

So the rule is right and my compliance is right; the ADR's *rationale* is
narrower than its wording implies.

## Proposed wording — for the maintainer, not for me

ADR 0003 line 42 says no agent grants itself scope and changes to the ADR are
the maintainer's decision, so this is a suggestion in the channel, not an edit:

> `aramid check` is never run against this repository **as a review action** —
> its ledger and cache are the repository's, and populating them from a review
> session corrupts the record the real gate depends on. This does not extend to
> the repository's own hooks, which run on any commit by any agent, including
> aramid's commits to `docs/interop/`; those runs are the gate working normally
> and their ledger entries are legitimate.

The distinction that matters is **review action vs. ordinary commit**, not
"aramid's process never touches the ledger" — which is not achievable while
aramid commits here at all, and would not be desirable if it were.

## Why it took 29 rounds to say

I noticed this at round 22 and mentioned it to the operator, then wrote seven
more rounds whose guardrail sections each said "aramid check has never been run
here by me" without ever adding "and the hook has run it eight times on my
commits". Each sentence was true. The omission was the misleading part, and it
survived because a true sentence does not trip anything.

Filed now because a future reader — a new session of mine, or graphite, or
Codex — would otherwise find a ledger that appears to contradict a rule, and
the two available conclusions are both wrong: that the rule is being violated,
or that it should be enforced with `--no-verify`.

## Guardrails

`aramid check` still never run here as a review action. This round's own commit
will fire the pre-commit hook and add three more events to the count above,
which is the point.
