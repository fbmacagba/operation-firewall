# Round 7 — test-strategy review through aramid's actual domain: blue/red-team + TDD gate

Written directly by aramid's agent. Round 2 reviewed the PRD through the
narrower slice of aramid's experience (hook chaining, config-merge
mechanics). aramid's own README opens with its real identity: "A red/blue
-team security & quality oversight engine." This round applies the part of
that identity Round 2 left unused — the TDD gate (red-first proof, mutation
testing, mutation-score drift) and the red-team gate (Phase 2b's evidence
-bound adversarial review) — against Operation Firewall's own test strategy,
which is a closer match to this domain than hook mechanics ever was.

Every claim below cites the PRD section it responds to and the aramid
mechanism it's drawn from, so it can be checked against both sources rather
than taken on argument alone.

## 1. "Tests pass" is not "tests ever proved anything" — red-first proof applies here

PRD §21 (definition of done): "Operation-bound approval and replay
protection pass adversarial testing." §17 Milestone 2 exit criteria: "FR-030
through FR-045 pass end to end." §16.1: "Zero approval replay,
target-substitution, cross-session, or expired-token successes in the
security suite."

All of these are phrased as *passing* tests. None of them require that the
test was ever shown to fail against a vulnerable implementation. aramid's
red-first-proof gate exists precisely because a test that never went red
proves nothing about what it claims to guard — "a file whose tests all pass
on the pre-change tree was never red" (`README.md`, "Red-first proof").
The risk is structurally sharper here than in aramid's own case: aramid's
gate assumes a human or a separate PR authored the fix after the test; here,
per the PRD's own division of labor, Codex authors both the implementation
and (presumably) the security suite validating it, in the same session. A
test for "replay must fail closed" written by the same agent that just wrote
the replay-protection code, without ever being run against a naive/vulnerable
stand-in, is exactly the shape of test that passes for the wrong reason.

Recommend, as a Milestone 1/2 process requirement rather than a schema
addition: before a security-suite test (replay, cross-session, target
-substitution, monotonic-policy-violation) is accepted, it must be run once
against a deliberately naive or stubbed-out implementation and shown to
fail. This is the same mechanical check aramid's `red-proof` producer runs
automatically (base-tree rerun); Operation Firewall does not need aramid's
exact mechanism, but the invariant — "prove the test can fail before trusting
that it passes" — transfers directly and is currently unstated anywhere in
the PRD or milestones.

## 2. "Passing" is not "hard to defeat" — mutation testing applies to the policy engine specifically

aramid's own lesson, stated plainly in its docs: "a passing suite that can't
kill mutants is lying about coverage." The concrete case that motivated this
round: aramid's own `_deep_merge` (reported in Round 2/3, fixed in `87d302f`)
recurses into dicts correctly but silently replaces list-valued leaves
instead of unioning them — a one-line, easy-to-miss policy bug that no
existing test caught, because every existing test happened to check "the
right thing landed," never "a wrong-direction change is impossible." That is
exactly a surviving-mutant shape of bug: flip a merge direction, swap a
comparison operator, or drop a union in favor of a replace, and the visible
test suite still passes.

PRD §16.1's "zero critical false negatives" and §9.3's monotonic
policy-precedence requirements (FR-020 through FR-026) are precisely the
area with this shape of risk — deterministic logic, small in surface area,
catastrophic if inverted, and easy to test only in the "happy path landed"
direction rather than the "wrong path is blocked" direction. Recommend a
property-based test (Hypothesis or equivalent, once the implementation
language is chosen — PRD §20 open decision #1) with an explicit invariant:
for any generated org/user/repo policy triple, `merge(org, user, repo)` is
never less restrictive than `org` for any operation kind. This is the kind
of test aramid's own `_deep_merge` never had — "`_deep_merge` currently has
no such test" was the exact gap identified in Round 2 — and it is a
materially stronger check than the milestone's planned fuzz/conformance
suites, which exercise inputs against the corpus of cases someone thought to
write down, not the algorithm's claimed structural property.

## 3. A curated critical-operation corpus is a snapshot of what its authors thought of — treat it like aramid's regression pack, not like a one-time deliverable

PRD §16.1: "Zero critical false negatives in the release-blocking
critical-operation corpus." As written, this reads as a fixed test list
authored once, likely by Codex, at or before Milestone 1. aramid's own
regression-defense mechanism (`.aramid-rules/regression.yml`) takes a
different shape deliberately: it is compiled from *resolved findings* — real
things a reviewer (including the red-team LLM reviewer) actually caught —
and grows as an ongoing byproduct of review, not as an upfront artifact.
The difference matters because a corpus authored entirely upfront only
encodes what its authors already imagined; the gaps that matter are, by
definition, the ones nobody imagined yet.

Recommend the critical-operation corpus be explicitly specified as a living
artifact — every adversarial-review or red-team finding (see #4) that
identifies a new critical bypass gets compiled into the corpus as a
permanent regression case, mirroring aramid's pack-compile step — rather
than a Milestone-0/1 deliverable that is considered complete once written.

## 4. Fuzzing and property tests check inputs; they don't check whether the decision *logic* itself has a blind spot — that's what aramid's red-team layer is for

PRD §7.1 lists "adversarial, property, fuzz" test foundations; §12 requires
bounded parser/policy paths under fuzz. All of this is real and necessary,
and it's exactly aramid's *blue-team* layer (Phase 1: deterministic,
zero-judgment, exhaustive-over-inputs). What it structurally cannot do —
and what aramid's own blue-team layer also cannot do, which is why Phase 2b
exists — is catch a business-logic or access-control flaw that no one wrote
an input case for, because the flaw is in the *shape* of the decision, not
in a malformed input. aramid's Phase 2b (the LLM reviewer) exists
specifically for that OWASP slice: "broken access control (A01), security
misconfiguration (A05), authentication failures (A07), and business-logic
flaws — adversarial, judgment-based review that a regex or an AST rule
cannot do" (`README.md`). Every finding is evidence-bound (a verbatim quote
mechanically checked against the actual diff) and fresh CRITICALs get a
cross-provider refute before being trusted — specifically so an adversarial
review's own false positives don't get rubber-stamped either.

Operation Firewall's own policy/approval engine is the same category of
target: a judgment-heavy decision surface (what counts as sufficiently
"resolved," whether a target-set change is severe enough to invalidate an
approval, whether a rewritten operation still matches its original digest)
that fuzz/property tests exercise but don't independently *judge*. Recommend
an explicit adversarial-review pass over the policy engine and approval
verifier design itself — not just their test suites — before Milestone 2
locks in the approval-capability implementation. This does not require
building aramid's own LLM-reviewer machinery; it requires treating "has
someone tried, in earnest, to defeat this design on paper" as a distinct
gate from "does the code pass its own tests," the same separation aramid
maintains between Phase 1 and Phase 2b.

## 5. Bake-before-arm is a rollout pattern worth naming, not just a UX metric

PRD §13 UX requirements name the risk ("repeated low-risk prompts must be
addressed through better deterministic policy, not broad bypasses") and
§16.2 tracks it operationally ("policy override and repeated-prompt rate")
but the PRD has no stated *mechanism* for how a new or tightened policy rule
gets introduced without immediately breaking real usage on first contact.
aramid's answer to this exact problem is bake-then-arm: a new BLOCK-tier
check (semgrep's OWASP rules, the LLM reviewer, the TDD/mutation/red-proof
gates) ships WARN-only for a period, so false positives surface and get
tuned before anything actually blocks, and arming is always an explicit,
auditable operator action (`aramid arm`), never automatic. Recommend the
same phased-rollout shape for Operation Firewall's own policy engine as
new/stricter rules are introduced post-launch — the PRD already implicitly
wants this (§13), it just doesn't name a mechanism yet.

## Summary for whoever distills this

Five items, ranked by how directly they touch a stated MVP acceptance
metric: #2 (mutation testing on the policy merge) and #1 (red-first proof
for the security suite) bear most directly on §16.1's "zero" metrics and
FR-020–026/FR-030–045; #4 (adversarial review of the decision logic, not
just its tests) is the highest-leverage recommendation but the least
mechanical — it's a process gate to add, not a test framework to adopt; #3
and #5 are rollout/maintenance patterns rather than pre-launch blockers.
