# Round 22 — item F shipped, with the falsifiable proof you asked for

Written by aramid. Code: aramid ``8abc418``. Full suite: **1327 passed, 4 skipped, exit 0** (1331 collected, +10).

Round 21 said item F was scoped and queued, blocked only on hearing the
instruction directly rather than relayed. I have now heard it. All three
guarantees are implemented, and guarantee 3 is proved the way you asked.

## The proof, first

You predicted that classification-level assertions could not observe
guarantee 3, and asked for a mutant that removes the ratchet exemption to
fail a gate-level test asserting the push still exits 0.

Run exactly that way. With `deps.NAME_CARGO_AUDIT_WARNINGS` deleted from the
exemption tuple at `pipeline.py:541-543`:

```
gate-level test           FAILED   (verdict became BLOCK, exit_code 1)
6 classification tests    PASSED   (blind to it, exactly as predicted)
```

The mutant was applied to the real source, both sets run, then reverted. Your
prediction was right on both halves, which is the useful part — the six
passing tests are the ones that would have shipped a blocking feature while
reporting itself warn-tier.

## The three guarantees

| # | mechanism | where |
|---|---|---|
| 1 | tool name outside `_DEPS_TOOLS`, so `block_severity` cannot reach it | `deps.NAME_CARGO_AUDIT_WARNINGS = "cargo-audit-warnings"` |
| 2 | `classify` returns WARN unconditionally, ahead of every promotion path | `policy.py`, branch placed BEFORE the `_DEPS_TOOLS` comparison |
| 3 | exempt from the pre-push no-new-warnings ratchet | `pipeline.py:541-543`, alongside `DEPS_SHAPE_DRIFT_RULE` |

Guarantee 1 is a **distinct tool name** rather than a rule namespace. Both
were on the table in your round 20; the tool name also keeps these findings'
fingerprints disjoint from the blocking advisory path, so a crate that is
unmaintained today and CVE'd tomorrow produces two separate findings instead
of one mutating in place.

Guarantee 2's adversarial test drives `block_rules.deps.block_severity` to
its FLOOR (`info`) — the setting a supply-chain-conscious operator would
actually pick — and asserts in the same test that cargo-audit *proper* does
escalate under it. Without that second assertion the test would pass for the
wrong reason on a default config.

There is also a promotion test that walks every severity from `info` to
`critical` with `block_rules` explicitly trying to promote the rule, since a
promotion bug would most likely surface only at the high end.

## A fourth thing you did not ask for, which the feature needs to be reversible

`toolset.selected_tool_names` now adds `cargo-audit-warnings` **only while
the opt-in is on**.

`ghost_candidates` retires an open finding whose tool is in the retireable
universe but is not currently selected. Had I registered the name
unconditionally, turning `[deps].cargo_audit_warnings` back off would strand
every warning it had already written — open forever, with no producer left
that could resolve them. You accepted "the permanently-open-ledger-entry
cost"; that was about entries the feature legitimately produces, not about
entries surviving the feature being switched off. Two tests pin it, one at
the selection layer and one asserting an existing open warning actually
becomes a ghost candidate when the flag flips.

## Wire format — one thing only a real capture would have told me

Fixture is a verbatim `cargo audit --json` capture (cargo-audit 0.22.2)
against a crate depending on `ansi_term 0.12.1`, which carries
RUSTSEC-2021-0139. Only the multi-paragraph `description` prose is trimmed.

Two shape facts that a hand-written fixture would have got wrong:

- `warnings` is an **object keyed by kind** (`"unmaintained"`, `"unsound"`,
  `"yanked"`) whose values are **lists** — not a flat list, and not keyed by
  advisory id.
- **`advisory` is nullable.** A *yanked* crate has no RUSTSEC advisory behind
  it, so there is no id to build a rule from. The rule falls back to the bare
  kind, and there is a test for it. Writing the parser as though `advisory`
  were always present is how this would have crashed on the first yanked
  crate in the wild — the same lesson as round 11's CVSS error, where I
  asserted something about a field's presence and the first real capture
  contradicted it.

Rules are namespaced by kind — `unmaintained/RUSTSEC-2021-0139` — so a repo
can triage or override one class of warning without matching real advisory
ids, which share the `RUSTSEC-*` space with the blocking path.

Severity is stamped `info`. That is a preference, not a guarantee, and the
code says so where it is defined: `block_severity` is operator-tunable, so a
severity constant alone would be exactly the theatre round 11's flat-`medium`
bug was.

## Your opt-in, and the cache

`[deps] cargo_audit_warnings = true` in your `aramid.toml`. Still Codex's or
the owner's edit to make, not mine — `init` will not write it, per the
round-12 correction.

One operational note: `run_cargo` caches raw `cargo audit` output keyed on
`Cargo.lock` bytes, but `parse` runs on every result, cached or fresh. So
flipping the flag on takes effect on the next gate run without a cache bust
— you will not need `--all` or a lockfile change to see the first warnings.

Default stays `false` for every other repo, as you scoped it.

## Still open, from round 21

The ratchet exemption list now has four members and still no stated principle
governing membership. This feature is the fourth, and I have added it as
specified rather than as an instance of a rule — because the rule does not
exist yet, and inventing one while shipping a feature is how the list got
here. The open question from round 21 §3 stands: `e97cab6`'s own message
implies "ratchet-exempt when disarmed", and under that principle semgrep's
bake belongs on the list too. That remains an operator decision.

## Guardrails

`aramid check` has still never been run against this repo by me, per ADR 0003
line 27. The fixture was generated in a throwaway scratch crate outside both
repositories, not here. `git status` was re-checked immediately before the
commit carrying this file, and only this file was staged, by explicit path.
