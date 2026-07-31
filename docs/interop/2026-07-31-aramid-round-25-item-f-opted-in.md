# Round 25 — item F opted in here

Written by aramid, on the repo owner's instruction. Short round: the decision
was made in round 20 and the implementation shipped in round 22; this is the
one-line config change that turns it on.

```toml
[deps]
cargo_audit_warnings = true
```

## Measured before flipping it

`cargo audit --json` against this repo's current `Cargo.lock`, run directly
(not through `aramid check`):

```
vulnerabilities: 0
warning kinds  : []
```

**Zero of both.** So this is a no-op today — and that is the best moment to
turn it on rather than a reason to wait. Flip it now and the first crate that
goes unmaintained is visible the day it happens. Flip it after a few have
accumulated and they all arrive at once, which is how a useful signal becomes
noise someone mutes.

## Verified reachable, and reversible

The flag has to reach two places, not one, and both were checked against this
repo's real config:

```
cfg.deps                      = {'cargo_audit_warnings': True}
cargo-audit selected          = True
cargo-audit-warnings selected = True
```

The second selection line is the reversibility guarantee from round 22:
`selected_tool_names` registers the warnings tool **only while the opt-in is
on**, so turning it back off lets any warnings it wrote retire as ghost
candidates rather than stranding them open with no producer. Setting it to
`false` is a genuine undo, not just a mute.

## Reminder of what it can and cannot do

It can never block, by three independent mechanisms — outside the tunable
`deps.block_severity` comparison, `classify` returns WARN for it
unconditionally ahead of any `block_rules` promotion, and it is exempt from
the pre-push ratchet. The third is the one that would otherwise bite: an
unmaintained crate stays unmaintained, so a newly published RUSTSEC
informational advisory would arrive on a repo that changed nothing, with no
fix available and no exit but a suppression.

Those warnings will appear in `aramid status` as open findings and stay
there. That is the accepted cost from round 20 — visible and triageable, as
against the single pass/fail bit `scripts/verify.py` gives today.

The rule ids are namespaced by kind (`unmaintained/RUSTSEC-...`,
`yanked/...`), so you can triage or override one class without matching real
advisory ids, which share the `RUSTSEC-*` space with the blocking path.

## Guardrails

`aramid check` still never run here. The `cargo audit` invocation above was a
direct subprocess reading `Cargo.lock`; it wrote nothing to `.aramid/`.
`git status` re-checked immediately before staging; only `aramid.toml` and
this file staged by explicit path. Codex's in-flight `crates/ofw-adapter-codex/`,
`docs/milestone-1/`, the untracked ADR 0003 draft and the modified
`Cargo.lock`, `Cargo.toml`, `README.md` and `provenance/registry.json` were
left untouched.
