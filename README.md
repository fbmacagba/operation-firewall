# Operation Firewall

Operation Firewall is a clean-room, policy-driven safety boundary for AI agents that can mutate code, data, infrastructure, and external systems.

It evaluates typed operation intent rather than relying only on command-string deny lists. The design covers shell execution, filesystem and Git mutation, databases, cloud infrastructure, Kubernetes, infrastructure-as-code, and structured tool or API calls through a common contract.

> [!IMPORTANT]
> Operation Firewall is under active development. The contracts and first policy-engine slice are implemented, but runtime hooks, target resolvers, approval capabilities, and end-to-end enforcement are not. Do not treat the current repository as an active protection boundary.

## Project status

| Milestone | Status | Scope |
| --- | --- | --- |
| 0 — Foundation | Complete | Approved PRD, threat model, architecture decisions, v1 contracts, and clean-room provenance |
| 1 — Local decision core | In progress | Typed contracts, monotonic policy evaluation, strict bounded Codex envelope parsing, exact Bash/apply_patch payload extraction, read-only Git intent interpretation, repository-scope target resolution, and the `ofw` CLI implemented; path-operand resolution, policy bundle loading, audit construction, and approvals remain |
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
- `ofw-policy` — validated facts and selectors, immutable restriction union, duplicate identity rejection, bounded composition, canonical ordering, conservative evaluation, and separate diagnostics naming the rules an unavailable fact left unresolved.
- `ofw-core` — the built-in safety baseline. A `SupportedOperationProof` cannot be constructed from unknown or incomplete evidence, its baseline is derived from that evidence rather than accepted from the caller, and `decide` joins it with the policy restriction so an absent proof is always `indeterminate` and `NoRestriction` never becomes an allow on its own.
- `ofw-adapter-codex` — dependency-free, bounded parsing for the documented `PreToolUse` envelope and exact Bash/apply_patch payload subsets with typed fail-safe outcomes.
- `ofw-intent` — a closed POSIX tokenizer that refuses any command it cannot reduce to literal words, plus per-subcommand flag allowlists for a read-only Git subset (`status`, `rev-parse`).
- `ofw-resolve` — target resolution against explicit trusted configuration: native canonicalization, containment decided by path component rather than by text, and derived reversibility and blast radius. Target scope is keyed on the operation kind, never on the absence of extracted operands.
- `ofw-cli` — the non-interactive `ofw` binary: `hook codex-pre-tool-use`, `assess`, `doctor`, and `version`, with a dependency-free JSON writer.
- Draft 2020-12 JSON schemas for operation intent, decisions, errors, policy bundles, and audit events.
- Positive and negative contract fixtures with executable red-first vulnerability witnesses.
- Property-style monotonicity coverage plus retained counterexamples proving each security test can fail: last-writer-wins composition, inverted restriction ordering, unbounded composition, discarded unresolved-rule identity, a tokenizer that ignores operators, an allowlist that ignores unknown flags, containment decided by string prefix, containment decided before canonicalization, target scope inferred from absent operands, and a pipeline that trusts the envelope's `cwd`.

Monotonicity is currently guaranteed structurally rather than by check: `Restriction` has no `allow` variant and the only combinator is union, so a lower layer cannot express a weakening. `PolicyLayer` is recorded in rule identity but is not read during evaluation. Cross-layer precedence has one worked example rather than generated coverage, and the v1 deserializer that must reject a bundle rule with `effect: allow` — which the JSON Schema rejects today — is not yet written.

The built-in baseline closes the composition half of the `NoRestriction` advisory: policy silence can no longer reach an allow, because allow now requires a proof whose derived baseline is allow. The advisory is **addressed, not closed** — `EffectivePolicy::evaluate` remains public and still returns `NoRestriction`, so nothing yet forces a caller through `ofw_core::decide`. That becomes structural when the CLI is the single entry point.

Containment, environment, blast radius and reversibility are now resolver output rather than constructor arguments, for the repository-scoped read subset. A proof is correspondingly stronger than it was, and still bounded by what the resolver actually collects: platform-specific evidence — reparse points, mount and volume identity, alternate data streams, per-directory case sensitivity, Unicode normalization — is not gathered, so this is not yet the per-platform resolver matrix the design requires. Canonicalization does go through the platform's native call and does resolve links, so a symlink or junction leading out of the boundary resolves out of the boundary.

Canonical-path selectors still return `indeterminate`: the resolver's canonical targets are not yet threaded into policy facts. v1 contract deserialization, snapshot hashing, path-operand resolution, policy bundle loading, audit construction, approval capabilities, and live hook integration are not yet implemented.

## Repository layout

```text
crates/
  ofw-adapter-codex/   Strict bounded parsing and payload extraction for Codex
  ofw-cli/             The `ofw` binary: assess, doctor, and the Codex hook
  ofw-contracts/       Validated domain primitives
  ofw-core/            Built-in safety baseline and final decision composition
  ofw-intent/          Closed, non-executing shell and Git interpretation
  ofw-policy/          Monotonic restriction evaluation
  ofw-resolve/         Target resolution against trusted configuration
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

### Running the CLI

Trusted configuration comes from the environment and has **no defaults**. All three variables are required together; without them nothing can be placed and every operation denies.

```powershell
$env:OFW_WORKING_DIRECTORY = "F:\Projects\operation-firewall"
$env:OFW_REPOSITORY_BOUNDARY = "F:\Projects\operation-firewall"
$env:OFW_ENVIRONMENT = "local"   # local|development|test|staging|production|shared

cargo run -p ofw-cli -- doctor
Get-Content envelope.json | cargo run -p ofw-cli -- assess
Get-Content envelope.json | cargo run -p ofw-cli -- hook codex-pre-tool-use
```

A defaulted working directory would be whatever launched the hook, and a defaulted environment would be an assumption about consequence that nobody made. The envelope's own `cwd` field is never read: it is the agent's claim about where its command would run, and resolving against it would let the operation choose the boundary it is measured against.

Reading configuration from the environment is explicit and outside the repository, but it is **weaker than the design requires** — a bounded configuration file whose ownership and permissions are verified at startup. `ofw doctor` reports that gap rather than leaving it to be discovered.

**Every hook invocation currently denies, and that is correct.** Read-only Git operations can now be *proven* — a `SupportedOperationProof` exists and `decide` returns a real `ask` rather than `indeterminate` — but `ask` has no Codex wire representation and denies until Milestone 2 binds an approval. This slice produces the first proof, not the first allow.

The reason code records how far down the pipeline an operation actually reached:

| command | configuration | reason code |
| --- | --- | --- |
| `git status` | configured | `APPROVAL_REQUIRED` — proven; baseline asks |
| `git status` (outside the boundary) | configured | `BASELINE_DENIED` — proven; baseline denies |
| `git status` | absent | `TRUSTED_CONFIGURATION_MISSING` — interpreted; nothing to place it against |
| `git push --force` | either | `OPERATION_INTERPRETATION_UNSUPPORTED` — literal, outside the subset |
| `git status; rm -rf /` | either | `COMMAND_NOT_LITERAL` — refused, never partially parsed |

Containment is decided by comparing canonical paths **by path component**, not as text. A sibling directory whose name merely begins with the boundary's is outside it, and a traversal or symlink that leaves the boundary resolves outside it. Target scope is keyed on the operation kind rather than on "the interpreter extracted no paths" — those coincide today, and would stop coinciding the moment an operand-extraction bug dropped a pathspec.

**No Git command can be proven non-executing from its arguments alone**, and this is why `git status` settles at `ask` rather than `allow` even once resolution lands. Git consults repository-controlled configuration, and `core.fsmonitor`, `core.pager`, `diff.*.textconv` and external diff drivers all name programs Git will execute — set in `.git/config` by the repository, with no command-line flag involved. `ofw-intent` therefore reports every Git invocation as carrying an execution surface, and `ofw_core::evidence_from_intent` is the only sanctioned path from an interpreted intent to evidence precisely so that this cannot be bypassed by assembling evidence by hand.

Flags are allowlisted per subcommand rather than denylisted. The set of Git flags reaching an execution surface is open-ended — `--exec-path`, `--upload-pack`, `--ext-diff`, `--textconv`, `-c`, `--config-env`, pretty formats carrying directives — so a denylist would read as coverage while admitting the next one.

Deny is emitted as exit code 2 with the reason on stderr, leaving stdout empty. Codex fails **open** — malformed stdout, empty stdout with exit 0, an unrecognized output field, a timeout, and exit 1 all let the tool call proceed — so a partially written JSON deny object would be worse than no object at all, whereas an exit code cannot be partially written. The explicit allow object's shape is inferred from the documented deny form and is **not yet confirmed against a live Codex**; it is unreachable today and flagged in the code as an open item.

### Continuous verification

`.github/workflows/verify.yml` runs the same `scripts/verify.py` entry point on Linux, Windows, and macOS for every push to `main` and every pull request, so the local gate and the remote gate cannot drift apart. Actions are pinned to immutable commit identities. A green run is evidence for contract validation, formatting, Clippy, and the test suite on those platforms — not evidence of production enforcement.

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
