# Policy

This directory will contain versioned schemas and policy bundles after the decision model is approved.

Initial decision states:

- `allow` — sufficiently proven safe under active policy.
- `ask` — requires a bound approval capability.
- `deny` — prohibited under active policy.
- `indeterminate` — analysis did not complete or the adapter cannot establish required facts.

Policy files must never contain executable expressions or unbounded regular expressions. Repository-local policy may add restrictions but must not weaken user or organization policy.

