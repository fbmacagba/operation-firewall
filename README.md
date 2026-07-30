# Operation Firewall

Operation Firewall is a clean-room project for policy-driven safety controls around high-risk AI-agent operations.

The project is intentionally broader than a destructive-shell-command denylist. Its target enforcement surface includes shell execution, filesystem mutation, Git, databases, cloud infrastructure, Kubernetes, infrastructure-as-code, and tool/API calls.

## Status

Architecture and policy scaffold only. No runtime enforcement claims should be made until hooks, adapters, tests, and fail-safe behavior are implemented and independently verified.

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
- `docs/` — architecture, threat model, and design decisions.
- `tests/` — conformance, adversarial, fuzz, and integration plans.
- `scripts/` — development and validation helpers.

## Clean-room boundary

This project must not copy, translate, or mechanically adapt source code, tests, patterns, documentation, or rule data from `destructive_command_guard`. Requirements must be independently written from observable safety goals and public interface behavior. Record provenance for imported examples or third-party data.

## Next milestone

Define the versioned `OperationIntent` schema and implement a minimal pre-tool decision engine with `allow`, `ask`, and `deny` outcomes.

