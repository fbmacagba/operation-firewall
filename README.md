# Operation Firewall

Operation Firewall is a clean-room project for policy-driven safety controls around high-risk AI-agent operations.

The project is intentionally broader than a destructive-shell-command denylist. Its target enforcement surface includes shell execution, filesystem mutation, Git, databases, cloud infrastructure, Kubernetes, infrastructure-as-code, and tool/API calls.

## Status

Milestone 0 foundation approved: architecture decisions, v1 contracts, threat model, and clean-room provenance process are in place. No runtime enforcement exists yet, and no protection claim should be made until hooks, adapters, tests, and fail-safe behavior are implemented and independently verified.

## Design goals

- Classify typed operations, not only command strings.
- Resolve exact targets and blast radius before execution.
- Require explicit, operation-bound approval for high-risk actions.
- Prefer reversible or transactional alternatives.
- Fail safely on protocol drift and incomplete analysis.
- Keep the enforcement runtime small and independently auditable.
- Record structured, redacted audit events without storing secrets.

## Project layout

- `.codex-plugin/` — Codex plugin manifest.
- `skills/guarded-operations/` — behavioral workflow used by agents.
- `hooks/` — future deterministic pre-tool integration.
- `policy/` — future typed policy schemas and policy bundles.
- `provenance/` — clean-room source and imported-artifact registry.
- `docs/` — architecture, threat model, and design decisions.
- `tests/` — conformance, adversarial, fuzz, and integration plans.
- `scripts/` — development and validation helpers.

## Product requirements

The working product definition, release scope, functional requirements, security requirements, milestones, and acceptance criteria are maintained in [`docs/PRD.md`](docs/PRD.md).

## External review

[`docs/reviews/2026-07-30-aramid-findings.md`](docs/reviews/2026-07-30-aramid-findings.md) records peer-review findings on fail-safe posture, approval-capability concurrency, security-test evidence, and monotonic policy composition. [`docs/reviews/2026-07-30-aramid-response.md`](docs/reviews/2026-07-30-aramid-response.md) maps all eight priorities to accepted decisions and milestone gates.

## Clean-room boundary

This project must not copy, translate, or mechanically adapt source code, tests, patterns, documentation, or rule data from `destructive_command_guard`. Requirements must be independently written from observable safety goals and public interface behavior. Record provenance for imported examples or third-party data.

## Next milestone

Implement Milestone 1's minimal local decision core in Rust: strict envelope parsing, the documented shell/filesystem/Git subset, target resolution, monotonic policy evaluation, redacted audit-event construction, and validation/assessment CLI commands. Security-invariant tests must carry red-first evidence from their introduction.
