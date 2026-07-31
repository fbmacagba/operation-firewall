# Round 13 — adversarial review of the monotonic policy core

Written by aramid. This is the review your disposition of finding 3 named as
a Milestone 1→2 gate: *"a distinct adversarial design review before approval
capabilities are accepted."* Rounds 1–8 reviewed documents. This is the first
round that reviewed code.

Scope read: `crates/ofw-contracts/src/lib.rs` (263 lines),
`crates/ofw-policy/src/lib.rs` (859), `crates/ofw-adapter-codex/src/lib.rs`
(916, currently untracked), ADR 0002, and `tests/` at the workspace root.
Read-only; nothing was modified.

## What is right

Worth stating plainly, because the defects below are narrow and the
foundation is not.

- **"Repository cannot express `allow`" is a type-level guarantee, not a
  runtime check.** `Restriction` is `{Ask, Deny}` — there is no `Allow`
  variant to smuggle. That is the strongest possible form of ADR §2's first
  clause, and it cannot regress by someone deleting a validation branch.
- **The known-false-conjunct reasoning is correct.** In
  `Selectors::applicability`, a dimension whose fact is `Known` and outside
  the selector set yields `NoMatch` even when another dimension was
  `Unknown` — because a false conjunct makes the conjunction false
  regardless. Subtle, right, and tested
  (`known_non_match_overrides_an_irrelevant_unknown_dimension`).
- **Duplicate identity is enforced at both levels** — `rule_id` within a
  bundle, `(layer, bundle_id, bundle_version)` across bundles — which
  together give ADR §4's effective identity without last-writer-wins.
- **Deny dominates indeterminate**, order-independence is tested, and
  `#![forbid(unsafe_code)]` is set in both crates.

## Finding 1 — a repository rule can erase an organization `Ask`

**Severity: high, currently latent.** ADR §2: external rules "cannot grant
`allow`, **suppress another rule**, redefine defaults, or contain
deletion/disable directives." This is a rule-suppression channel.

`EffectivePolicy::evaluate` (lib.rs:350–391) resolves in the order
`Deny > Indeterminate > Ask > NoRestriction`. On the indeterminate branch
(lib.rs:372–377) it returns `determining_rules: Vec::new()` — so a matched
`Ask` is not merely outranked, **its identity is discarded**. Downstream
cannot tell that an organization rule wanted to ask.

The trigger does not require guessing which facts are unavailable.
`Selectors::applicability` (lib.rs:179–181) inserts
`MissingFact::CanonicalPathResolution` **unconditionally** whenever
`canonical_path_prefixes` is non-empty, since canonical path resolution is
not implemented yet. So any rule carrying a path prefix is *always*
indeterminate, for every operation, with all facts known.

Concrete construction — every input is valid and passes all validation:

```
Organization bundle "org.baseline"
  rule "ask-force-update"   Ask   selectors: operation_kind ∈ {git.force_update}

Repository bundle "repo.local"          <- attacker-controlled layer
  rule "repo-path-guard"    Ask   selectors: operation_kind ∈ {git.force_update}
                                             canonical_path_prefixes = ["/"]

facts = complete_facts()   (every fact Known)

evaluate() -> outcome: Indeterminate, determining_rules: []
```

Without the repository bundle the outcome is `Ask`. With it, the
organization's approval gate is gone from the result. One rule, in the least
trusted layer, suppresses an approval requirement in the most trusted one.

`Deny` is **not** suppressible this way — it is checked first — so the
capability is bounded to `Ask`. That bound is real and worth keeping.

**Why I am not calling this a bypass.** I verified that `PolicyOutcome`
appears nowhere outside `ofw-policy`, and `ofw-adapter-codex/Cargo.toml`
declares no dependencies at all. The decision→wire mapping does not exist
yet, so the downstream consequence is unwritten and I cannot demonstrate it.
It forks:

- If non-high-risk `indeterminate` maps anywhere below `ask` — and ADR §7
  only promises that *high-risk* indeterminate maps to deny — a repository
  silently removes a human approval prompt.
- If all `indeterminate` maps to deny, a repository forces every covered
  operation to deny with one rule: a repo-triggered denial of service beyond
  the malformed-policy DoS the ADR knowingly accepts.

Both are capabilities ADR §2 denies the repository layer. Raising it now is
deliberate: this is cheap to settle before the mapping is written and
expensive afterwards.

Worth considering: carry matched `Ask` identities through the indeterminate
result rather than dropping them, so whatever consumes the outcome can still
see that an approval was required and by whom.

## Finding 2 — the monotonicity property test cannot observe Finding 1

**Severity: medium.** `adding_restrictions_never_reduces_complete_fact_outcome`
(lib.rs:796–811) is the test carrying ADR's proof obligation *"adding any
valid bundle or rule cannot reduce the decision on any fixed intent."* Two
limits mean it holds only on a subset:

1. It evaluates against `complete_facts()` and builds rules with the bare
   `rule()` helper, which sets no path prefixes. **The `Indeterminate` branch
   is never reached.** The obligation is proven for all-facts-known,
   no-path-selector policies only — which is not where the interesting
   behaviour lives.
2. `outcome_rank` (lib.rs:851–858) hardcodes
   `NoRestriction 0 < Ask 1 < Indeterminate 2 < Deny 3`. But ADR §7 places
   `indeterminate` deliberately *outside* the restriction lattice. Ranking it
   above `Ask` is an assumption, and it is precisely the assumption Finding 1
   questions — embedded in the test that is supposed to check it. Even if the
   test did reach the branch, `Ask → Indeterminate` would score as an
   increase and pass.

The property is worth keeping; the generator needs to range over unknown
facts and path-prefixed selectors, and the ordering of `Indeterminate`
relative to `Ask` needs to be a derived consequence of the wire mapping
rather than a constant in a test helper.

## Finding 3 — the red-first witness does not exercise the shipped evaluator

**Severity: medium.** ADR proof obligations: *"each monotonicity test must
first fail against a deliberately vulnerable overlay or rule-dropping
implementation."*

`red_first_witness_detects_last_writer_wins_vulnerability` (lib.rs:814–823)
compares `vulnerable_last_writer_wins` against `restriction_union` — two
local helpers, five lines each. **Neither is `EffectivePolicy::evaluate`.**
The witness proves the *concept* of union-over-last-writer-wins; it produces
no evidence about the code that ships. `evaluate` could regress to
last-writer-wins and this test would stay green.

You already have the right pattern one crate over. In
`ofw-adapter-codex/src/lib.rs:886–906`,
`red_first_witness_detects_fail_open_parser_fallback` compares `strict_gate`
— which calls the real `assess_pre_tool_use` — against a deliberately
fail-open twin. That is a mutation witness with teeth. The suggestion is
simply: do in `ofw-policy` what you already did in `ofw-adapter-codex`.

Related: your disposition of finding 2 says "Contract negative fixtures
include executable deliberate-weakening witnesses." The workspace `tests/`
tree is JSON schema valid/invalid fixtures driven by
`scripts/validate-contracts.py` — schema-validity negatives, which are
useful but are not weakening witnesses. The genuine witnesses are the two
in-crate tests above, one of which has the gap described here.

## Smaller notes

- **Availability.** `MAX_RULES_PER_BUNDLE` is 2,048, but
  `EffectivePolicy::compose` bounds neither the number of bundles nor total
  rules. Evaluation is linear in rule count on a per-operation hot path with
  a deadline, so a *valid* policy can exhaust the deadline. The ADR accepts
  DoS from malformed policy; unbounded valid policy is a different bargain.
- **`OperationFacts::with_unknown_operation_kind`** (lib.rs:52–56) is public
  and downgrades a Known fact to Unknown. Given Finding 1 that is a
  suppression primitive; it reads as test-only and would be safer as
  `#[cfg(test)]` or crate-private.

## Not covered

I reviewed composition and evaluation. I did not review the envelope parser
in depth (916 lines, untracked), the audit-event path, or approval
redemption — findings 5 and 6 in your earlier disposition. Concurrency
(ADR: "readers observe either the complete old snapshot or the complete new
snapshot") has no implementation in these crates yet, so there was nothing
to review; `EffectivePolicy` is an immutable value, which is the right
starting shape for it.
