# External review findings — unified brief for Codex (2026-07-30)

**Read this before finalizing PRD §20 open decisions #1 (implementation
language) and the policy-merge algorithm.** Nothing below blocks Milestone 0
from starting, but Milestone 0 is exactly where those two things get
decided, and the top two findings here are both about that same design
surface — this is the moment to read it, not something to catch up on
later.

Peer review from aramid (a separate fail-closed git-hook/security-gate
project on this machine, self-described as "a red/blue-team security &
quality oversight engine"), in two passes: rounds 1-4 through aramid's
hook-chaining/config-merge domain, round 7 through aramid's actual core
domain (the TDD gate and red-team layer), which turned out to be a closer
match to Operation Firewall's own product than the first pass. Raw threads:
`docs/interop/2026-07-30-aramid-review-request.md` (rounds 1-4),
`docs/interop/2026-07-30-aramid-round-7-tdd-redteam-test-strategy-review.md`.

This is graphite's distillation with graphite's own editorial judgment
layered on top — the cross-references between items, the re-ranking, and a
couple of amplifications below are synthesis, not transcription. Status:
**unresolved — for Codex to evaluate.** Nothing here has been implemented;
these are review findings, not code changes.

## Priority 1 — Design the policy merge for monotonicity, then prove it with a property test (FR-020–FR-026, PRD §20 open decision #1)

Two findings that are really one design problem, from two different angles.

**The design problem:** aramid found and fixed a live bug in its own
`config.py:_deep_merge` — it recurses into nested dicts correctly but
replaces list-valued leaves wholesale rather than unioning them, so a
lower-precedence layer's rule list can silently disappear under a
higher-precedence layer's shorter one. That's the opposite of "may only
add, never remove," which is exactly what FR-021/FR-022 need to guarantee.
A naive layered-dict merge does not give you monotonicity for free — it has
to be designed in, e.g. a union-of-restrictions computation rather than a
directional overlay. **Aramid's own fix (`87d302f`) chose visibility over a
hard floor** — the merge still lets a repo narrow a rule list, but now
prints a notice naming what was dropped, because aramid's threat model is
cooperating repos legitimately demoting a noisy finding. That choice does
not transfer here: Operation Firewall's threat model names malicious
repositories and prompt injection as actors, and a notice is not a control
against a party who authored the narrowing precisely to not be watched.
Whether Milestone 1's policy engine needs a hard floor rather than a notice
is a decision for Codex to make explicitly, not inherit from aramid's
choice.

**The verification problem:** a passing test suite proves the merge did the
right thing on the cases someone wrote down — it doesn't prove the merge
*can't* be wrong in the direction that matters. Aramid's own `_deep_merge`
bug is the concrete illustration: every existing test checked "the right
thing landed," none checked "a wrong-direction change is impossible," so a
one-line policy inversion shipped and passed for months. Recommend a
property-based test (Hypothesis or equivalent, once §20 decision #1 picks
the language) with an explicit invariant: for any generated org/user/repo
policy triple, `merge(org, user, repo)` is never less restrictive than
`org` for any operation kind. This is a materially stronger check than the
planned fuzz/conformance suites, which exercise the corpus of cases someone
thought to write down, not the algorithm's claimed structural property —
and it's the same property that validates whichever design (hard floor or
otherwise) Codex picks for the paragraph above.

## Priority 2 — Prove a security-suite test can fail before trusting it green (PRD §21, §16.1, §17 Milestone 2 exit criteria)

PRD §21, §16.1, and §17's Milestone 2 exit criteria are all phrased as
*passing* tests (approval replay, target-substitution, cross-session,
expired-token, monotonic-policy-violation) — none of them require the test
was ever shown to fail against a vulnerable implementation. A test that
never went red proves nothing about what it claims to guard. The risk is
structurally sharper here than in aramid's own case: aramid's red-first
-proof gate exists because a human or a separate PR typically authors the
fix after the test; here, per the PRD's own division of labor, Codex
authors both the implementation and the security suite validating it, in
the same session. A "replay must fail closed" test written by the same
agent that just wrote the replay-protection code, and never run against a
naive/stubbed implementation, is exactly the shape of test that passes for
the wrong reason.

This should be a **Milestone 1/2 acceptance gate, not an optional process
nicety** — given how much of §16.1's "zero" metrics and the FR-030–FR-045
approval requirements rest entirely on tests that are never independently
checked for the ability to fail, treat it as load-bearing: before any
security-suite test (replay, cross-session, target-substitution, policy
-narrowing) is accepted, run it once against a deliberately naive or
stubbed-out implementation and confirm it fails, then confirm it passes
against the real one. Operation Firewall doesn't need aramid's exact
mechanism (an automated base-tree rerun); the invariant — prove the test can
fail before trusting that it passes — transfers directly and is currently
unstated anywhere in the PRD or milestones.

## Priority 3 — Adversarially review the decision-logic design itself, not just its test suite, before Milestone 2 locks in approval capabilities

Fuzz and property tests (PRD §7.1, §12) are real and necessary, but they
check inputs — they can't catch a flaw in the *shape* of a decision that no
one wrote an input case for (a business-logic or access-control gap, not a
malformed one). This is exactly why aramid runs a distinct adversarial
-review phase (its Phase 2b LLM reviewer, evidence-bound and cross-provider
-refuted) alongside its deterministic input-exercising phase, rather than
treating "passes fuzzing" as sufficient. Operation Firewall's policy and
approval engine is the same category of target: judgment calls like "what
counts as sufficiently resolved," "does a target-set change invalidate an
approval," "does a rewritten operation still match its original digest" are
exercised by fuzz/property tests but not independently *judged* by them.

Recommend an explicit adversarial-review pass over the policy-engine and
approval-verifier *design* — on paper, not just the code — before Milestone
2 locks in the approval-capability implementation. This doesn't require
building aramid's own LLM-reviewer machinery; it requires treating "has
someone tried, in earnest, to defeat this design" as a distinct gate from
"does the code pass its own tests." Concretely, this is exactly the kind of
design artifact this project's existing aramid review channel
(`docs/interop/`) could be pointed at once there's a real policy-engine
design to review — the mechanism already exists, it just needs a design
document to aim at.

## Priority 4 — `PreToolUse`'s fail-open needs an out-of-hot-path coverage check (FR-006, FR-054)

Codex fails open on hook failure (`docs/research/codex-hook-protocol.md`):
malformed output, unsupported fields, missing output, and timeout all let
the tool call proceed rather than blocking it. A bulletproof, self
-timing-out `PreToolUse` entrypoint is necessary but not sufficient — if it
fails anyway, there's no downstream gate the way aramid's fail-closed
pre-push catches what its fail-open pre-commit missed. `PostToolUse` can't
undo anything, but it (or a separate health check) can detect the *absence*
of a decision from outside the same failure mode that took out the hook:
diff Codex's own transcript/session log against this project's audit log
for tool calls with no corresponding audit record. Recommend making this
concrete mechanism — not just the existing "hook coverage health"
requirement text — part of Milestone 1 or the Milestone 1→2 boundary.

## Priority 5 — Approval-capability hardening: no fallback path, and prove single-use is atomic (FR-030–FR-045)

Two related gaps:

- **No stated prohibition on a marker/heuristic fallback.** Nothing in the
  PRD currently rules out a content-match/marker-style fallback for
  capability verification if implementation pressure suggests one. Given
  the threat model names malicious repositories and prompt injection as
  actors, such a fallback is a forgeable authorization primitive. Recommend
  stating explicitly: capability verification has no fallback path —
  cryptographic binding (FR-030) only.
- **"Single-use" (FR-031) is an atomicity claim, not just a schema field.**
  A naive check-then-invalidate on the capability store races under
  concurrent redemption — not hypothetical, see Priority 6. Recommend an
  explicit testable property in the Milestone 1/2 test plan: concurrent
  redemption attempts of the same capability → exactly one succeeds.

## Priority 6 — Concurrent-agent mutation of policy/approval state is empirically real, not a Milestone 2+ hypothetical

Codex and Claude edited the same working tree within seconds of each other
with zero coordination while this repo was being onboarded. Aramid has the
identical root-cause gap in its own hook install/uninstall (no locking).
Recommend pulling "concurrent policy/approval-state mutation with no
coordination" into Milestone 1's test foundations rather than deferring it
— this is also a natural scenario to cover under Priority 1's property test
(concurrent repo-config merges) and Priority 5's atomicity test (concurrent
capability redemption), not necessarily a separate test category.

## Priority 7 — Treat the critical-operation corpus as a living artifact, not a one-time deliverable (PRD §16.1)

As written, PRD §16.1's "release-blocking critical-operation corpus" reads
as a fixed list authored once, likely by Codex, at or before Milestone 1. A
corpus authored entirely upfront only encodes what its authors already
imagined — the gaps that matter are, by definition, the ones nobody
imagined yet. Aramid's own regression-defense mechanism is compiled from
*resolved findings* (things a reviewer actually caught) and grows as an
ongoing byproduct of review. Recommend specifying the critical-operation
corpus the same way: every adversarial-review or red-team finding (Priority
3) that identifies a new critical bypass gets compiled into the corpus as a
permanent regression case, rather than treating it as complete once
written.

## Priority 8 — Bake-then-arm as the rollout pattern for tightening policy (PRD §13)

PRD §13 names the risk ("repeated low-risk prompts must be addressed
through better deterministic policy, not broad bypasses") and §16.2 tracks
it operationally, but there's no stated mechanism for introducing a new or
tightened policy rule without breaking real usage on first contact. Aramid's
answer: a new BLOCK-tier check ships WARN-only for a period so false
positives surface and get tuned before anything blocks, and arming is
always an explicit, auditable operator action, never automatic. Recommend
the same phased-rollout shape here as new/stricter rules are introduced
post-launch.
