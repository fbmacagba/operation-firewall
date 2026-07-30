# Operation Firewall

Operation Firewall is a clean-room, policy-driven safety boundary for AI agents that can mutate code, data, infrastructure, and external systems.

It evaluates typed operation intent rather than relying only on command-string deny lists. The design covers shell execution, filesystem and Git mutation, databases, cloud infrastructure, Kubernetes, infrastructure-as-code, and structured tool or API calls through a common contract.

> [!IMPORTANT]
> Operation Firewall is under active development. The contracts and first policy-engine slice are implemented, but runtime hooks, target resolvers, approval capabilities, and end-to-end enforcement are not. Do not treat the current repository as an active protection boundary.

## Project status

| Milestone | Status | Scope |
| --- | --- | --- |
| 0 — Foundation | Complete | Approved PRD, threat model, architecture decisions, v1 contracts, and clean-room provenance |
| 1 — Local decision core | In progress | Typed contracts and monotonic policy evaluation implemented; parsing, adapters, resolution, audit construction, and CLI remain |
| 2 — Approval and Codex integration | Not started | Bound approvals, replay protection, real `PreToolUse` integration, and enforcement diagnostics |
| 3 — Broader adapters | Not started | Database, Kubernetes, cloud, IaC, and MCP adapters |

The authoritative scope and acceptance criteria are in the [product requirements](docs/PRD.md).

## Security model

Operation Firewall is designed around these invariants:

- Unknown, malformed, unsupported, or timed-out high-risk operations never silently become clean allows.
- Policy decisions are deterministic and explainable; an AI model is never the sole authorization control.
- External policy is restriction-only. Repository policy may add restrictions but cannot weaken user or organization policy.
- Approval must be bound to the exact normalized operation, resolved targets, actor, session, environment, expiry, and use count.
- Audit contracts exclude raw credentials, authorization headers, sensitive payload bodies, and canonical operation bodies.
- The trusted enforcement path stays small and independent from UI, analytics, updates, and reporting.
- Security claims remain limited to explicitly tested host, protocol, tool, and platform coverage.

See the [threat model](docs/threat-model.md), [architecture](docs/architecture.md), and [monotonic policy ADR](docs/decisions/0002-monotonic-policy-composition.md) for the full rationale.

## How decisions work

1. A protocol adapter strictly validates an event and produces a versioned `OperationIntent`.
2. A platform resolver establishes concrete targets, boundaries, environment, reversibility, and blast radius.
3. The policy engine unions all validated restriction bundles and selects the most restrictive applicable result.
4. The core returns `allow`, `ask`, `deny`, or `indeterminate` with determining rules and safe rationale.
5. Later milestones will bind approvals, revalidate targets, integrate with the host hook, and emit already-redacted audit events.

The Codex `PreToolUse` wire exposes only `allow` and `deny`. Internal `ask` must complete inside the hook before a wire decision is emitted; failure, rejection, timeout, or expiry maps to wire `deny`.

## Implemented today

The dependency-free Rust workspace currently contains:

- `ofw-contracts` — bounded identifiers, namespaced names, versions, operation effects, environment classes, reversibility, blast radius, policy layers, and restrictions.
- `ofw-policy` — validated facts and selectors, immutable restriction union, duplicate identity rejection, canonical ordering, and conservative evaluation.
- Draft 2020-12 JSON schemas for operation intent, decisions, errors, policy bundles, and audit events.
- Positive and negative contract fixtures with executable red-first vulnerability witnesses.
- Property-style monotonicity coverage and a deliberate last-writer-wins counterexample proving the security test can fail.

Canonical-path selectors currently return `indeterminate` until a platform resolver supplies boundary-safe canonical path facts. JSON parsing, snapshot hashing, target resolution, audit construction, CLI commands, approval capabilities, and live hook integration are not yet implemented.

## Repository layout

```text
crates/
  ofw-contracts/       Validated domain primitives
  ofw-policy/          Monotonic restriction evaluation
policy/
  schemas/v1/          Normative JSON Schema contracts
tests/fixtures/        Contract fixtures and red-first witnesses
docs/                  PRD, architecture, threat model, research, and ADRs
hooks/                 Planned deterministic host integration
skills/                Agent-facing guarded-operations workflow
provenance/            Clean-room source and artifact registry
scripts/               Deterministic development verification
```

## Development

### Prerequisites

- Rust `1.97.1` with `rustfmt` and `clippy` (pinned by `rust-toolchain.toml`)
- Python 3.11 or newer
- Python `jsonschema` for development-time contract validation

No third-party crate is currently part of the enforcement runtime.

### Verify the repository

Run the complete contract, formatting, lint, and test suite from the repository root:

```powershell
python -B scripts/verify.py
```

Run individual checks when developing a focused change:

```powershell
python -B scripts/validate-contracts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
```

Every new security-invariant test must first demonstrate that it fails against a deliberately weakened implementation for the claimed reason. See the [test strategy](tests/README.md).

### Graphite and Aramid

This repository uses Graphite as its shared local code graph and Aramid for deterministic security and quality gates.

```powershell
graphite check .
graphite doctor
aramid doctor
aramid status
```

Graphite-first navigation is required for non-trivial cross-file work; follow [GRAPHITE.md](GRAPHITE.md). Aramid runs through the repository Git hooks and executes the full verification command before push; see [ARAMID.md](ARAMID.md). A clean result from either tool is evidence for its documented checks, not proof of complete security coverage.

## Documentation

- [Product requirements](docs/PRD.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [OperationIntent and contract semantics](policy/contracts-v1.md)
- [Policy and schema guide](policy/README.md)
- [Clean-room provenance process](docs/clean-room-provenance.md)
- [Codex hook protocol research](docs/research/codex-hook-protocol.md)
- [External review findings](docs/reviews/2026-07-30-aramid-findings.md)
- [External review response](docs/reviews/2026-07-30-aramid-response.md)

## Clean-room boundary

Do not copy, translate, mechanically adapt, or derive implementation, patterns, tests, documentation, or rule data from `destructive_command_guard`. Requirements and tests must be independently written from this repository's safety goals and public interface behavior. Imported examples, specifications, datasets, and policy data require provenance and license review under the [clean-room process](docs/clean-room-provenance.md).

## License

Operation Firewall is available under the [MIT License](LICENSE).
