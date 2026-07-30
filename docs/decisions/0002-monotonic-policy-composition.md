# ADR 0002: Restriction union with a hard monotonic floor

- Status: Accepted
- Date: 2026-07-30
- Deciders: Operation Firewall maintainers

## Context

Organization, user, and repository policy must compose without allowing a less-trusted layer to weaken a more-trusted restriction. The threat model includes malicious repositories and prompt injection, so reporting that narrowing occurred is not an adequate control.

A conventional deep merge is unsafe for this requirement: key replacement, list replacement, deletion markers, ordering, or duplicate identifiers can erase a higher-layer restriction while producing a syntactically valid configuration.

## Decision

Adopt a hard monotonic floor. Policy bundles are restriction sets, not mutable configuration overlays.

1. Validate each supplied bundle independently and completely before activation.
2. External bundle rules may return only `ask` or `deny`. They cannot grant `allow`, suppress another rule, redefine defaults, or contain deletion/disable directives.
3. Compose the effective snapshot as the set union of all validated rules from organization, user, and repository layers. Lists and maps are never directionally overlaid.
4. Give every rule a globally unambiguous identity within its bundle. The effective identity is `(layer, bundle_id, bundle_version, rule_id)`. Duplicate effective identities are a validation error, not last-writer-wins.
5. Canonically sort only for deterministic serialization and diagnostics. Order does not affect semantics.
6. Evaluate every applicable rule. Join outcomes on the restriction lattice `allow < ask < deny`; the maximum outcome wins. A clean `allow` exists only when the built-in supported-operation baseline proves the operation safe and no external restriction matches.
7. Keep `indeterminate` outside the restriction lattice. Missing required facts, invalid supplied policy, unsupported security-critical schema versions, evaluation failure, or deadline exhaustion produces `indeterminate`; trusted integration policy maps high-risk `indeterminate` to a deny wire response.
8. Bind each decision and approval to the digest of the complete immutable effective policy snapshot.

Repository policy therefore can add an `ask` or `deny`, but it has no representable operation that removes or relaxes an organization or user restriction. This is enforcement, not notice-only visibility.

## Selector semantics

Policy selectors use a bounded declarative vocabulary. Present selector dimensions are ANDed; values within a dimension are ORed. No arbitrary code, regular expressions, negation, override priority, dynamic import, environment expansion, or network lookup is permitted in the policy language.

Unknown selector fields or unsupported versions fail validation. A rule that requires unavailable evidence does not silently fail to match; evaluation becomes `indeterminate` when the unavailable fact could affect applicability.

## Activation and failure behavior

Policy activation is atomic. The engine evaluates against one immutable snapshot. A new snapshot becomes active only after all layers validate and its digest is computed. Concurrent readers retain the prior valid snapshot until the new snapshot commits.

If a supplied repository policy is malformed, the engine reports an unhealthy configuration and returns `indeterminate` for covered mutating operations; it does not discard the malformed layer and claim the remaining snapshot is fully effective. This permits a malicious repository to cause a denial of service, but not to create a policy bypass. Recovery is removal or correction of the repository policy through an explicitly trusted path.

## Required proof obligations

- Property: adding any valid bundle or rule cannot reduce the decision on any fixed intent.
- Property: permutation of layers and rules does not change the decision or snapshot digest after canonicalization.
- Negative cases: list replacement, empty-list narrowing, duplicate IDs, deletion markers, unknown selector fields, and repository attempts to express `allow` are rejected.
- Mutation/red-first gate: each monotonicity test must first fail against a deliberately vulnerable overlay or rule-dropping implementation, with the failure evidence retained, before its green result counts.
- Concurrency: readers observe either the complete old snapshot or the complete new snapshot, never a partial composition.

## Consequences

- Repository owners cannot use repository policy to waive a noisy higher-level rule. Waivers must occur at the layer that owns the restriction, be separately authorized, and produce a new versioned bundle.
- Denial-of-service through malformed untrusted policy is an explicit availability trade-off in favor of preventing silent narrowing.
- Policy authoring is less expressive than a general configuration language. That limitation is intentional for explainability and bounded evaluation.

## Rejected alternatives

- **Deep merge with precedence:** replacement semantics can erase restrictions and make security depend on data-structure details.
- **Deep merge plus narrowing notice:** a malicious repository is not deterred by a notice.
- **Priority-number rules:** creates an override channel and makes monotonicity difficult to reason about.
- **Repository-local waivers:** repository state is inside the attacker-controlled trust zone and cannot authorize weakening a higher layer.

## Rollback and compatibility

The hard floor is a v1 semantic guarantee. A future policy language may add selector dimensions but may not add a lower-layer weakening mechanism under the same major version. Rolling back an engine must fail closed if it cannot understand an active policy snapshot's schema version.
