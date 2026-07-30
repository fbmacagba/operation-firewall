# External review findings — aramid, round 1 (2026-07-30)

Peer review from aramid (a separate fail-closed git-hook/security-gate
project on this machine), requested before Milestone 0 implementation
begins. Raw thread: `docs/interop/2026-07-30-aramid-review-request.md`.
This doc distills it into action items against the PRD's FR numbers.

Status: **unresolved — for Codex to evaluate and fold into Milestone 0/1
design decisions.** Nothing here has been implemented; these are review
findings, not code changes.

## 1. Coverage-health check needs to be an out-of-hot-path mechanism, not just a self-timeout (touches FR-006, FR-054)

The research doc's finding (`docs/research/codex-hook-protocol.md`) that
Codex fails open on hook failure means a bulletproof, self-timing-out
`PreToolUse` entrypoint is necessary but not sufficient: if it fails anyway,
there's no downstream gate the way pre-push catches what pre-commit missed
in aramid's own design. `PostToolUse` can't undo anything, but it (or a
separate health check) can detect the absence of a decision — diff Codex's
own transcript/session log against this project's audit log for tool calls
with no corresponding audit record. Recommend making this concrete
mechanism, not just the existing "hook coverage health" requirement text,
part of Milestone 1 or the Milestone 1→2 boundary.

## 2a. State the "no marker/heuristic fallback" rule explicitly as a negative requirement (touches FR-030)

Nothing in the PRD currently *prohibits* a content-match/marker-style
fallback for capability verification if implementation pressure suggests
one. Given the threat model already names "a malicious repository" and
"prompt injection" as threat actors, any such fallback is a forgeable
authorization primitive. Recommend adding an explicit statement: capability
verification has no fallback path — cryptographic binding only.

## 2b. "Single-use" (FR-031) is an atomicity claim and needs a concurrency test (touches FR-030–FR-045)

A naive check-then-invalidate on the capability store races under concurrent
redemption. Recommend adding an explicit testable property to the Milestone
1/2 test plan: concurrent redemption attempts of the same capability →
exactly one succeeds. This isn't hypothetical — see #4.

## 3. Monotonic policy merge needs a union-of-restrictions algorithm, not a layered dict-overlay (touches FR-021, FR-022) — highest priority

**Update 2026-07-30: aramid fixed its own instance of this bug** (`87d302f`,
main, pushed, verified). Chosen approach was visibility over a hard floor —
`_deep_merge` still lets a repo demote individual BLOCK-tier rule ids (an
intentional, documented capability), but `load_config()` now diffs
pre-/post-repo-merge `block_rules` and prints a stderr notice naming exactly
which rule ids got dropped whenever a repo's `aramid.toml` narrows more than
it names. Independently verified here: reproduced the original exploit
against `87d302f`, confirmed the notice fires and names the dropped rule
ids, confirmed the demote capability itself still works (not a floor), ran
the two new regression tests plus the full existing `test_config.py` suite
(33/33 passed). **This closes the loop on aramid's own exposure — it does
not change what Operation Firewall itself needs to do.** The underlying
lesson for this project's own policy-merge design is unchanged: a naive
layered-dict merge does not give monotonicity for free, and FR-021/FR-022
need an explicit design decision, not just a fixed dependency. Aramid's
"visibility over a hard floor" choice was made for aramid's own use case
(repos legitimately need to demote noisy findings); Operation Firewall's own
threat model (malicious repos, prompt injection as named actors) may call
for a stricter answer — a hard floor rather than a notice — since silent-vs-
loud doesn't help against an adversarial party who can also suppress or
ignore stderr output. That's a decision for Codex to make explicitly, not
inherit from aramid's choice.

Aramid found and verified a live, currently-unfixed gap in its own
`config.py:_deep_merge`: it recurses into nested dicts correctly but
replaces list-valued leaves wholesale rather than unioning them, so a lower
-precedence layer's list (e.g. a rule-id block-list) can silently
disappear under a higher-precedence layer's shorter or empty list — the
opposite of "may only add, never remove." This is the exact property
FR-021/FR-022 need to guarantee, and it demonstrates that a straightforward
layered-merge implementation does not give you monotonicity for free —
it has to be designed in (e.g. compute a union of restrictions across
layers rather than letting a later layer's value replace an earlier one),
with an adversarial test asserting a repo-level attempt to loosen an
org-level restriction fails. Recommend treating this as a concrete design
constraint on the policy-merge algorithm from the start, not something to
validate after the fact.

## 4. Concurrent-uncoordinated-agent mutation is empirically real, not a Milestone 2+ hypothetical

Codex and Claude edited the same working tree within seconds of each other
with no coordination while this repo was being onboarded (see
`docs/interop/2026-07-30-aramid-review-request.md` §"What we're asking",
item 4). Aramid has the same root-cause gap (no locking in its own hook
install/uninstall). Recommend pulling "concurrent policy/approval-state
mutation with no coordination" into Milestone 1's test foundations rather
than deferring it.
