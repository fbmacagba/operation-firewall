# Architecture

Status: Approved for Milestone 0

## Decision pipeline

```text
Untrusted tool event
  -> host protocol adapter and strict envelope validation
  -> typed OperationIntent v1
  -> target and environment resolution
  -> immutable effective policy snapshot
  -> deterministic ALLOW | ASK | DENY | INDETERMINATE
  -> approval verifier when required
  -> host wire adapter (Codex v1: ALLOW | DENY only)
  -> host execution
  -> postcondition observation
  -> already-redacted audit event
```

The internal decision model and host wire model are separate contracts. Codex `PreToolUse` currently supports only `allow` and `deny`; an internal `ask` must complete through Operation Firewall's approval channel before the hook returns. Failure to obtain or verify approval becomes a valid deny response. The adapter must never emit unsupported `ask` output.

## Trust boundaries

| Boundary | Untrusted side | Trusted responsibility |
|---|---|---|
| Host event | Tool name, arguments, working directory, model/session labels, repository content | Bound and strictly validate the envelope before interpretation. |
| Repository | Repository policy, paths, symlinks, hooks, scripts, fixtures | Treat as attacker-controlled; it may add restrictions but cannot grant authority. |
| Policy activation | Organization/user/repository bundle files | Validate atomically and build an immutable restriction union. |
| Resolution | Agent-supplied target strings and environment labels | Derive canonical targets from read-only OS/VCS evidence and preserve uncertainty. |
| Approval | UI text, terminal input, agent statements | Verify only a cryptographic capability bound to the exact intent, target set, session, environment, policy snapshot, expiry, and use count. No fallback marker is allowed. |
| Audit | Internal decision facts | Redact before crossing into persistence; persistence never receives raw secrets or sensitive payload bodies. |
| Host execution | Valid hook response | Recognize that the host can fail open if the hook fails; monitor coverage independently. |

## Core components

### Protocol adapters

Adapters translate one documented host protocol range into versioned contracts. They do not contain policy. A recognized mutating event that cannot be translated produces a typed `indeterminate` result.

The Codex adapter must impose an internal deadline well below the host's 600-second timeout and contain all failures at the outermost entrypoint. Any panic, parser error, policy error, audit-construction error, or self-timeout must be converted to a minimal, well-formed exit-code-2 deny path. This reduces but cannot eliminate the host's fail-open risk.

### Operation intent

`OperationIntent` is the canonical proposed-operation contract. It contains bounded actor, session, source, operation, target, context, privilege, reversibility, blast-radius, precondition, evidence, and redaction metadata. It is immutable after evaluation begins. Approval and audit contracts refer to its canonical digest.

JSON uses UTF-8 and JSON Schema Draft 2020-12. Canonical digests use RFC 8785 JSON Canonicalization Scheme followed by SHA-256. Numeric values that cannot be represented consistently across implementations are prohibited from digest-bearing structures.

Schema evolution rules:

- `schema_version` uses a `major.minor` string.
- A major version changes required semantics or removes compatibility; unsupported majors fail validation.
- A minor version may add optional, bounded fields only. Security-critical unknown fields are rejected by v1 schemas rather than ignored.
- Persisted decisions record the exact schema version and canonical digest.
- Adapters declare the exact input protocol range and output contract versions they support.

### Target and environment resolver

Resolvers are platform-specific behind typed interfaces. They operate read-only, enforce allocation and traversal limits, and return both facts and uncertainty. Agent labels never establish tenant, production, repository, or privilege identity by themselves.

An approval-eligible target must be canonical, concrete, and revalidatable. Globs, variables, symlinks, junctions, reparse points, mounts, aliases, and remote identifiers remain explicit evidence; unresolved high-risk targets cannot receive a clean allow.

### Policy engine

The engine implements [ADR 0002](decisions/0002-monotonic-policy-composition.md). It validates each restriction bundle, creates an immutable union, evaluates all applicable rules, and selects the most restrictive result on `allow < ask < deny`. `indeterminate` represents evaluation failure or missing security-critical facts and is not equivalent to a policy outcome.

There is no lower-layer override, deletion, exclusion, priority, last-writer-wins field, or notice-only narrowing path. Policy order is non-semantic. Decisions bind the complete effective snapshot digest and list every determining rule.

### Approval verifier

Approvals are short-lived signed capabilities. Verification has no marker, content-match, environment-variable, terminal-code, or heuristic fallback. Redemption is an atomic state transition; concurrent redemption of the same single-use capability must result in exactly one success.

Approval presentation and capability verification are separate. Codex does not receive the internal capability or `ask` state; it receives only the final `allow` or `deny` wire outcome.

### Audit

Redaction occurs before event persistence. Audit events contain stable identifiers, digests, policy provenance, safe rationales, lifecycle state, and health indicators—not raw credentials, authorization headers, commands containing secrets, or sensitive payload bodies.

Audit failure is a typed health state. The trusted integration policy determines whether a given operation denies on audit unavailability; the effect is never implicit.

### Coverage monitor

The synchronous hook cannot prove its own continued presence. A separate, out-of-hot-path health mechanism compares host-observed tool-call identifiers with Operation Firewall decision/audit identifiers and reports missing decisions. `PostToolUse` may supply observations but is not an enforcement control and cannot undo effects.

The product may report enforcement active only for a host/version/tool path that passes a recent allow probe, deny probe, registration integrity check, and coverage reconciliation within a documented freshness window.

## Implementation structure

The core uses stable Rust and Cargo as specified in [ADR 0001](decisions/0001-enforcement-core-language-and-workspace.md). External contracts remain language-neutral. UI, policy authoring, analytics, update checks, fleet management, and reporting stay outside the trusted runtime.

The first Codex execution boundary advises and blocks; it does not broker execution. Constrained execution remains a later adapter/broker capability because the current hook protocol hands execution back to the host after `allow`.

## Explicit unsupported and unhealthy states

- Hook not registered, disabled, stale, or absent on a host path.
- Unsupported host, hook event, protocol version, tool, operation kind, or contract major version.
- Malformed, oversized, deeply nested, or deadline-exhausting input.
- Target, tenant, environment, privilege, or blast radius cannot be established.
- Supplied policy is invalid or cannot be activated atomically.
- Approval key, clock, replay store, audit path, or coverage monitor is unhealthy.
- Post-approval target or precondition revalidation differs from the bound facts.

These states are surfaced as typed errors and/or `indeterminate` decisions. For recognized high-risk operations in the Codex adapter they produce a valid deny wire response. They never support a claim of complete interception or protection.

## Test and review gates

- Every security invariant test must be shown failing against an intentionally vulnerable or stubbed implementation before its passing result is accepted. Retain the red/green evidence in CI artifacts or an auditable test record.
- The monotonic composition algorithm requires property and mutation tests, not only examples.
- Policy and approval designs receive an explicit adversarial design review before Milestone 2 implementation is accepted.
- Every new bypass finding becomes a permanent critical-operation corpus case.
- New blocking rules follow a bake-then-arm process: observe in warn-only simulation, measure and tune, then activate through an explicit audited trusted-policy change. Simulation can never weaken an already active restriction.

## Rollback and compatibility

Policy and contract activation is atomic. Retain the last known valid trusted snapshot for diagnostics and rollback, but never label it current when a supplied policy fails validation. Binary rollback is permitted only when the older binary supports every active contract and policy major version; otherwise startup is unhealthy and high-risk operations deny.
