# Round 11 — point-by-point response to Codex's seven observations

Written by aramid. This is the mapping round 10 deliberately withheld.

Round 10 said the feedback had been relayed verbally and that aramid had not
read its text, so no point-by-point response would be attempted. The text has
since been recovered verbatim, so here it is, answered against the actual
wording rather than a summary of it.

Three points are fixed in code. One has closed on its own since it was
written. Three are accurate descriptions of intended behaviour, and one of
those is intended for a reason worth stating explicitly.

Evidence note: findings below marked *(ledger)* come from reading
`.aramid/ledger.db` in this repo read-only (`mode=ro`). Nothing in this repo
was written except this file.

---

## 1. Cargo workspace classified as python, "package manager: none"

CORRECTION (see round 16): marked **Fixed** below, but only half was.
`37a9bd6` closed the dependency-auditing half; the "Rust-specific gate
discovery" half named in the same sentence had no implementation at all --
aramid had no Rust linter and its semgrep ruleset carries zero Rust rules.
Closed for gate discovery by the clippy runner in `bc04c8d`; Rust *security*
rule depth remains open. The original text is left below as the round-11
record.

> Stack detection classified this Cargo workspace as python with "package
> manager: none." That is inaccurate for the repository and means Aramid does
> not natively provide Rust dependency auditing or Rust-specific gate
> discovery.

**Correct, and fixed** (`37a9bd6`). `detect_stacks()` had no `Cargo.toml`
case; `detect_package_manager()` did not know `Cargo.lock`. Measured against
this tree after the fix:

```
detect_stacks          -> ['python', 'rust']
detect_package_manager -> cargo
```

`python` correctly remains — `scripts/verify.py` is real Python and is your
configured test command. The fix adds Rust, it does not remove Python.

Already visible in your own ledger *(ledger)*: the two pre-commit runs that
landed round 10 record

```
"selected": ["cargo-audit", "gitleaks", "python", "ruff", "semgrep", "tests"]
```

`cargo-audit` is in that list because Rust is now detected here.

## 2. No native cargo audit supply-chain gate

CORRECTION (see round 15): the claim below that a flat `medium` meant
"**no Rust advisory could block a push at any severity**" is **wrong**. A
new-findings ratchet escalates any NEW finding to BLOCK at pre-push
regardless of tier, so on an established ledger it blocked either way. What
`7e67097` actually fixes is the fresh-ledger path, where only *genuinely*
BLOCK findings survive: pre-fix, a CVSS 9.8 advisory was silently baselined
on any fresh clone, CI runner or reset ledger, since `.aramid/` is
gitignored. Narrower than stated, and arguably worse. Measured both arms;
the original text is left below as the round-11 record.

> Our custom scripts/verify.py compensates by running Cargo formatting,
> Clippy, and tests, but it does not add a native cargo audit supply-chain
> gate.

**Correct, and now provided** (`37a9bd6`, corrected by `6efed44` and
`7e67097`). aramid has a native cargo-audit runner: `Cargo.lock` selects it,
findings carry RUSTSEC ids, and it runs at pre-push.

Worth being blunt about how close this came to being theatre. The first
version stamped every advisory `medium`. Because `deps.block_severity`
defaults to `critical`, that meant **no Rust advisory could block a push at
any severity** — a supply-chain gate that reports and never stops anything.
It was justified in a code comment by the claim that RUSTSEC advisories
usually carry no CVSS score, which turned out to be false the first time real
`cargo audit --json` output was captured. Severity is now banded from the
CVSS v3.1 vector. Verified end-to-end through `policy.classify` at pre-push:

```
RUSTSEC-2021-0003  critical -> block   (was medium -> warn)
RUSTSEC-2020-0071  medium   -> warn    (local, availability-only)
```

That failure mode is structurally the same one your point 6 identifies: a
control that looks like enforcement and isn't. It is the more interesting
half of this response, and it was found by running the code against this
repo rather than by the test suite, which was green throughout.

## 3. `aramid doctor` proves the test binary exists, not that the suite runs

> aramid doctor confirms that the configured test executable exists but
> explicitly does not prove the suite runs. We separately proved it through
> the pre-push hook.

**Correct, intended, and deliberately so for a security reason** — not a
limitation to be fixed later. `probe_tests()` says it outright in source:
"Resolving argv[0] proves the binary exists, NOT that the suite [runs]".

The reason matters to your threat model. `[tests].command` comes from
`aramid.toml`, which ships with a cloned repository — it is **external
input**. `probe_tool()` executes `<name> --version`, and its S603
justification depends on `name` being a hardcoded literal. So doctor resolves
the configured command through `toolpath.resolve`, which is pure lookup and
executes nothing, and never hands it to `probe_tool`. A doctor that "proved
the suite runs" would be a doctor that executes an attacker-supplied command
on `git clone` + `aramid doctor`.

Your workaround is the right one: proving it through the pre-push hook is
exactly where execution belongs.

## 4. Scheduled review drain had never completed a run

> The scheduled review drain is installed, but current status still says
> last drain: never, with one item queued. Therefore, deterministic
> commit/push gates are proven, while scheduled asynchronous review has not
> yet completed an end-to-end production run.

**True when written; no longer true.** Your ledger now records a completed
end-to-end drain *(ledger)*:

```
seq 45  run_started        {"gate": "drain", "tools": []}   2026-07-31T01:31:02Z
seq 53  queue_item_drained {}                               2026-07-31T01:32:54Z
```

with six `consumer_run_finished` events. Two items were queued (the
Milestone-0 foundation commit and the monotonic-policy-core commit), one was
coalesced into the other, and one drained. Scheduled asynchronous review has
now had its production run — roughly two minutes end to end.

## 5. Semgrep and LLM enforcement still in bake

> Semgrep and LLM enforcement remain in the intentional bake period.
> Findings are visible, but those layers are not fully blocking yet.

**Correct, and working as configured.** Your `aramid.toml` carries
`semgrep_block_armed = false` and `bake_started = "2026-07-30"`. Bake-then-arm
is the intended rollout: observe, tune, then arm deliberately. Nothing to fix
— this is the design your own ADR 0002 disposition also adopted ("warn-only
simulation, measurement/tuning, and explicit audited activation").

## 6. Policy-list merge could replace packaged BLOCK rules with only a notice

> Aramid's documented policy-list merge can replace packaged BLOCK rules and
> only emit a notice. That makes repository-controlled Aramid configuration
> unsuitable as a hard security floor against a malicious repository.

**Correct, and fixed properly** (`a71356f`). This had already been "fixed"
once as a stderr notice, and that was not good enough for exactly the reason
you gave: a notice is not a floor, and a contributor who can edit
`aramid.toml` can equally silence stderr.

`block_rules` is now an enforced floor. A repo's `aramid.toml` may only ADD
block-tier rule ids to what the operator's own machine config established;
anything it drops is unioned back in, and the notice now names what was
*restored* rather than what was lost. Operator-level demotion in
`~/.aramid/config.toml` is unaffected — it lives inside the floor. So the
attempt stays visible while no longer being able to succeed.

## 7. Pre-commit is fail-open; pre-push is the real gate

> Pre-commit is intentionally fail-open under its time budget; pre-push is
> the actual fail-closed gate.

**Correct.** Two independent confirmations:

`GATE_RUNNER_KEYS` splits the tiers —

```
PRE_COMMIT: ["gitleaks", "ruff"]
PRE_PUSH:   ["gitleaks", "semgrep", "eslint", "typecheck", "deps", "tests"]
```

and the managed hook shims swallow different exit codes: pre-commit exits 0
on status 2 *or* 3, pre-push only on 2.

Your ledger shows the split concretely *(ledger)* — the same run that
*selected* six tools only *ran* two:

```
{"gate": "pre-commit", "tools": ["gitleaks", "ruff"],
 "selected": ["cargo-audit", "gitleaks", "python", "ruff", "semgrep", "tests"]}
```

This is also the practical answer to when you will first see cargo-audit
execute: on your next `git push`, not your next commit.

---

## Summary

| # | Point | Status |
|---|---|---|
| 1 | Rust workspace misdetected | Fixed — `37a9bd6` |
| 2 | No native cargo audit gate | Delivered — `37a9bd6`, `6efed44`, `7e67097` |
| 3 | doctor proves binary, not suite | Intended — security boundary, see above |
| 4 | Drain never completed a run | Closed — completed 2026-07-31T01:31Z |
| 5 | Semgrep/LLM still baking | Intended — as configured |
| 6 | Policy merge not a hard floor | Fixed — `a71356f` |
| 7 | Pre-commit fail-open | Intended — confirmed two ways |

All four aramid commits are on `main` and, because aramid is installed
editable from its source tree on this machine and your hooks invoke
`python -m aramid`, they are already live here with no reinstall.

Standing caveat from round 10, unchanged: cargo-audit has been verified at
the parser and classifier layers and against real captured `cargo audit
--json` output, but not yet through a live gate run on a Rust repo — running
one here would have written to your ledger and cache.
