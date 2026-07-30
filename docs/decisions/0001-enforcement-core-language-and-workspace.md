# ADR 0001: Rust enforcement core and Cargo workspace

- Status: Accepted
- Date: 2026-07-30
- Deciders: Operation Firewall maintainers

## Context

The enforcement hot path must parse untrusted events, resolve targets, evaluate deterministic policy, and emit a valid host response under strict resource and time bounds. It must run locally on Windows, macOS, and Linux without a network dependency. A crash or malformed response is security-significant because the initial Codex host integration fails open when a hook fails.

The external architecture review reinforced that the policy model must make security invariants structurally testable and that security tests must be demonstrated red against a vulnerable implementation before their green result is accepted.

## Decision

Implement the enforcement core in stable Rust using Cargo and the Rust 2024 edition. Pin the toolchain in `rust-toolchain.toml` when the workspace is bootstrapped; upgrades require an explicit pull request, contract tests, adversarial tests, and a rollback note.

Use a workspace with narrow crates and one-way dependencies:

```text
crates/
  ofw-contracts/       versioned wire/domain contracts and strict validation
  ofw-policy/          restriction-set loading, composition, and evaluation
  ofw-resolver/        platform-specific target and environment resolution
  ofw-core/            bounded orchestration and decision production
  ofw-audit/           redaction and audit-event construction
  ofw-approval/        capability verification and atomic redemption (Milestone 2)
  ofw-adapter-codex/   Codex envelope and wire-response adapter
  ofw-cli/             assessment, policy validation, diagnostics, and doctor UX
```

Only `ofw-contracts`, `ofw-policy`, `ofw-resolver`, `ofw-core`, the required portion of `ofw-audit`, and the active adapter belong in the trusted hook runtime. The CLI, policy authoring, reporting, updates, and analytics remain outside it. Crate boundaries may be collapsed when measurement shows separate crates add complexity without improving isolation, but dependency direction and trust boundaries must remain explicit.

JSON Schema Draft 2020-12 is the language-neutral contract source for external JSON. Rust types must be generated from or checked against these schemas; handwritten types may not silently diverge.

Dependencies are admitted only after package validation, license and maintenance review, feature minimization, and a documented reason. Default features must be disabled when they expand the attack surface without a required capability. No network client belongs in the ordinary local decision path.

## Why Rust

- Memory safety without a garbage-collected runtime reduces parser and concurrency risk in a hostile-input boundary.
- Native binaries avoid interpreter discovery and dependency drift in a synchronous hook.
- Cargo supports reproducible lockfiles, feature control, cross-platform tests, fuzzing, and property testing.
- Rust makes explicit error handling, bounded data structures, immutable policy snapshots, and atomic capability redemption practical.

Rust does not make the design safe by itself. Panics, resource exhaustion, unsafe code, flawed authorization logic, platform path behavior, and supply-chain compromise remain in scope. `unsafe` is forbidden in project crates by default; an exception requires a dedicated ADR, safety proof, tests, and review.

## Consequences

- Initial delivery is slower than a scripting-language prototype, especially for Windows path resolution and host integration.
- The project must measure cold start and process-spawn overhead, not infer performance from language choice.
- The outer hook adapter needs a minimal failure guard and a self-deadline comfortably below the host timeout. Internal errors become a typed `indeterminate` decision and a valid deny wire response; panics must not unwind across the entrypoint.
- Cross-compilation, artifact signing, SBOM generation, and reproducible release verification become release work, not Milestone 0 implementation work.

## Rejected alternatives

- **TypeScript/Node.js:** strong ecosystem and development speed, but adds runtime discovery, dependency surface, and startup variability to the trusted synchronous hook.
- **Python:** excellent prototyping and property-testing support, but interpreter and environment drift are undesirable in the enforcement boundary.
- **Go:** credible native deployment and operational simplicity, but Rust provides stronger compile-time ownership and type modeling for the parser, policy, and capability boundaries. Go remains a reasonable fallback if measured Rust portability or staffing cost becomes unacceptable.

## Rollback and compatibility

The external JSON contracts are language-neutral. If Rust proves operationally unsuitable before a production release, another implementation may replace it only if it passes the same schema, conformance, adversarial, fuzz, resource-budget, and red-first security gates. No persisted contract may change merely to accommodate an implementation rewrite.
