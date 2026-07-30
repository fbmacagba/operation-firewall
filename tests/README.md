# Test strategy

## Required suites

- Schema and protocol conformance.
- Policy `allow`/`ask`/`deny`/`indeterminate` invariants.
- Monotonic policy composition properties and mutation tests.
- Target containment, symlink, junction, reparse-point, mount, and path canonicalization.
- Approval replay, expiry, substitution, scope-confusion, and atomic concurrent redemption attacks.
- Shell and tool-call adversarial corpus.
- Complexity, allocation, input-size, recursion, and timeout budgets.
- Property, mutation, fuzz, integration, and supported-platform tests.
- Recovery, audit redaction, coverage reconciliation, concurrency, and retry behavior.

## Red-first security evidence

A security test is not accepted merely because it passes. Before acceptance, run it against an intentionally vulnerable, weakened, or stubbed implementation and retain evidence that it fails for the claimed reason. Then run the same test unchanged against the real implementation and retain the green result.

This applies from Milestone 0 onward to schema boundaries, policy narrowing, approval replay/substitution, cross-session use, expiry, atomic redemption, target revalidation, redaction, and other adversarial claims. CI artifacts or a committed test-evidence record must identify the test, vulnerability mutation/stub, expected failure, observed failure, and corrected implementation result.

The Milestone 0 contract validator implements executable red-first witnesses: each negative fixture is rejected by the real schema and accepted after one deliberate weakening that represents the vulnerability the fixture guards.

## Critical-operation corpus

The corpus is a living regression artifact. Every confirmed adversarial-review, incident, fuzz, or red-team finding that exposes a new critical bypass must add a minimized permanent case with provenance and red-first evidence. The corpus is never declared complete.

## Design review gate

Before Milestone 2 approval capabilities are accepted, reviewers must adversarially examine the policy and approval designs themselves, separately from executing their tests. Findings and resolutions become review records; critical bypasses also enter the corpus.

## Current contract validation

Run:

```powershell
python -B scripts/validate-contracts.py
```

Fixtures are under `tests/fixtures/contracts/v1/{valid,invalid}`. `manifest.json` binds each pair to its schema and deliberate vulnerability witness.
