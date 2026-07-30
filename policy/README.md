# Policy and contracts

The approved v1 contracts use JSON Schema Draft 2020-12:

- `schemas/v1/operation-intent.schema.json` — canonical proposed-operation contract.
- `schemas/v1/decision.schema.json` — deterministic `allow`, `ask`, `deny`, or `indeterminate` result.
- `schemas/v1/error.schema.json` — safe integration and enforcement error envelope.
- `schemas/v1/policy-bundle.schema.json` — bounded restriction-only organization, user, or repository policy.
- `schemas/v1/audit-event.schema.json` — already-redacted lifecycle and health event.

Cross-field and cross-contract requirements that JSON Schema cannot prove are normative in [`contracts-v1.md`](contracts-v1.md). Structural validation must complete before bounded semantic validation.

External policy bundles contain restrictions only: rules may produce `ask` or `deny`, never `allow`. The effective policy is the union of every validated layer, and evaluation selects the most restrictive applicable result. No overlay, list replacement, deletion marker, priority, or lower-layer waiver exists. See [ADR 0002](../docs/decisions/0002-monotonic-policy-composition.md).

Policy selectors are bounded and declarative. Present selector dimensions are ANDed; values within a dimension are ORed. Policy files cannot contain executable expressions, regular expressions, environment expansion, dynamic imports, or network lookups.

Validate schemas and their positive, negative, and red-first witness fixtures with:

```powershell
python -B scripts/validate-contracts.py
```

The validator dependency is development tooling, not part of the enforcement runtime. Before adding it to a managed environment, follow `AGENTS.md` package-validation requirements.

The initial dependency-free Rust implementation lives in `crates/ofw-contracts` and `crates/ofw-policy`. It implements validated domain primitives, bounded selector inputs, immutable restriction union, deterministic canonical ordering, duplicate-identity rejection, and conservative evaluation. It does not yet parse these JSON contracts or compute the policy snapshot digest.
