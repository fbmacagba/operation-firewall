# Milestone 1 completion design

Status: approved architecture; written specification pending user review

Date: 2026-08-01

## Purpose

Finish Operation Firewall Milestone 1 as a production-oriented local decision
core without claiming production enforcement. The result must be deterministic,
bounded, auditable, clean-room, OS-agnostic, LLM-agnostic, and agent-agnostic.
Codex remains the first proven host adapter; future Claude CLI, Cursor, VS Code,
Antigravity, and other integrations translate their protocols into the same core
contracts without changing authorization semantics.

Milestone 1 ends with a runnable non-interactive CLI and a minimal Codex hook
runner for conformance and health probes. Signed approvals, replay protection,
approval key management, synchronous `ask` resolution, and production active-
enforcement claims remain Milestone 2.

## Security invariants

1. A valid host envelope is not proof that its operation is supported or safe.
2. `PolicyOutcome::NoRestriction` is never mapped directly to `allow`.
3. Only a typed built-in supported-operation proof can establish an allow-like
   baseline; policy can only preserve or increase its restriction.
4. Unknown syntax, semantics, targets, platform behavior, health, or elapsed
   deadline produces `indeterminate`, never a clean allow.
5. Shell and patch inputs are parsed as data. The decision core never executes,
   expands, evaluates, imports, dot-sources, or invokes them.
6. Relative paths resolve from an explicit trusted working directory. Agent or
   repository labels cannot establish tenant, environment, privilege, or
   repository identity.
7. Resolver implementations use native platform evidence and never emulate a
   different operating system's path semantics.
8. Audit construction and persistence receive already-redacted data only. Raw
   commands, patch bodies, secrets, credentials, and authorization headers do
   not cross into persistence.
9. Audit unavailability makes every mutation `indeterminate`. A positively
   proven read-only operation may continue only with explicit degraded health.
10. The Codex hook maps internal `ask` and `indeterminate` to a valid deny until
    Milestone 2 supplies and verifies an exact bound approval.
11. Every security-invariant test retains a vulnerable or stubbed red-first
    witness that the same assertion rejects.

## Scope

### Included

- Full typed Rust representations for the Milestone 1 portions of the v1
  invocation, intent, decision, error, audit, policy-snapshot, evidence, target,
  and health contracts.
- Strict serialization and deserialization with unknown-field rejection and the
  existing schema bounds.
- Agent-neutral invocation contracts and host-adapter metadata.
- Closed, bounded PowerShell and POSIX shell parsing.
- Closed, bounded Git command interpretation shared by both shell dialects.
- Strict apply-patch operation extraction.
- Windows, Linux, and macOS local filesystem target resolution.
- Built-in baseline proof and deterministic policy orchestration.
- Redacted local audit construction and persistence.
- Non-interactive CLI assessment, policy validation, diagnostics, and Codex hook
  modes.
- Red-first, negative, abuse, property, fuzz, concurrency, cross-platform,
  deadline, and performance evidence for the supported subset.
- Pinned cross-platform CI, dependency review, SBOM generation, and reproducible
  release verification for Milestone 1 artifacts.

### Excluded

- Arbitrary shell, PowerShell expression, or script interpretation.
- General-purpose command safety classification.
- Command execution or constrained brokering.
- Environment, variable, alias, function, glob, or command-substitution
  expansion.
- Database, Kubernetes, cloud, IaC, MCP, or remote API adapters.
- Signed approval creation, redemption, replay state, key management, or user
  approval presentation.
- Production active-enforcement claims.

## Workspace architecture

The workspace adds five crates and retains the three existing crates:

```text
ofw-contracts
  ├── ofw-intent ────┐
  ├── ofw-resolver ──┤
  ├── ofw-policy ────┼──> ofw-core ──┐
  ├── ofw-audit ─────┘               ├──> ofw-cli
  └── ofw-adapter-codex ─────────────┘
```

The actual dependency graph remains acyclic:

- `ofw-contracts` depends only on vetted serialization and digest libraries.
- `ofw-intent` depends on `ofw-contracts`.
- `ofw-resolver` depends on `ofw-contracts` and narrowly scoped platform APIs.
- `ofw-policy` depends on `ofw-contracts`.
- `ofw-audit` depends on `ofw-contracts` and vetted cross-platform file locking.
- `ofw-core` depends on contracts, intent, resolver, policy, and audit.
- `ofw-adapter-codex` depends on contracts and keeps Codex-specific parsing.
- `ofw-cli` is the only executable and composes core plus host adapters.

No UI, analytics, updater, remote reporting, plugin loader, or dynamic library
loading enters the trusted runtime.

## Agent- and LLM-neutral boundary

`AgentInvocation` is the core input boundary. It contains:

- bounded actor, session, host-instance, tool, and tool-use identifiers;
- declared host adapter ID and version;
- an explicit trusted shell dialect when the payload is a shell command;
- an agent-neutral payload variant such as shell command or apply patch;
- explicit trusted working context references;
- a digest of the raw request, not the raw request itself.

Model names, agent product names, host permission labels, and repository-provided
environment labels remain untrusted metadata. They may be audited in bounded
redacted form but cannot grant authority or select a weaker policy.

Every future host adapter must publish an exact protocol revision, supported
tool paths, failure behavior, and conformance fixtures. A host path without a
verified pre-execution blocking mechanism is `monitor_only` or `unsupported`,
never `protected`.

## Decision pipeline

```text
untrusted host event
  -> strict host adapter
  -> AgentInvocation
  -> closed intent parser
  -> IntentCandidate
  -> native platform resolver
  -> ResolvedIntent + RevalidationFingerprint
  -> built-in SupportedOperationProof
  -> immutable policy snapshot evaluation
  -> final Decision + Health
  -> redacted AuditEvent
  -> audit persistence
  -> structured CLI or host response
```

Each stage receives immutable typed input and returns a typed success or
indeterminate error. No stage repairs malformed input or silently drops an
unknown field.

## Intent parsing

### Shared bounds

- Command bytes: 65,536.
- Tokens: 512.
- Token bytes: 4,096.
- Parsed operations: 256.
- Candidate targets: 256.
- Path bytes: 4,096.
- Parser nesting: 32 where the grammar nests.
- Evaluation uses a caller-supplied deadline checked at bounded intervals.

Exceeding any limit returns a stable typed error without echoing payload data.

### POSIX subset

The parser accepts one simple command with POSIX single quotes, double quotes,
and backslash escaping only where the resulting token is literal. It rejects
operators and constructs including `|`, `||`, `&&`, `;`, redirection, command
substitution, parameter expansion, arithmetic expansion, process substitution,
heredocs, globs, tilde expansion, assignments, functions, and scripts.

Supported command families are:

- metadata/read: `pwd`, `ls`, `stat`, and bounded `test` path predicates;
- filesystem mutation: `mkdir`, `touch`, `cp`, `mv`, `rm`, and `chmod`;
- Git: the exact Git subset below.

Only documented flags with deterministic target meaning are accepted. `--`
ends options where the command supports it. Unknown, repeated-conflicting, or
target-obscuring flags return `indeterminate`.

### PowerShell subset

The parser accepts one command invocation with literal unquoted tokens, literal
single-quoted strings, and double-quoted strings only when they contain no
interpolation or escape requiring evaluation. It rejects pipelines, statement
lists, redirection, subexpressions, variables, splatting, script blocks,
member/index access, providers other than the filesystem, encoded commands,
dot-sourcing, invocation operators, aliases, functions, and scripts.

Supported cmdlet families are:

- metadata/read: `Get-Item`, `Get-ChildItem`, and `Test-Path`;
- filesystem mutation: `New-Item`, `Copy-Item`, `Move-Item`, and `Remove-Item`;
- Git: the exact Git subset below.

Filesystem commands require literal-path semantics. A supported cmdlet form
that lacks a native literal-path parameter must reject wildcard metacharacters.
Parameter abbreviations and positional ambiguity are unsupported.

### Git subset

The interpreter recognizes exact `git` invocations and rejects aliases,
external subcommands, arbitrary `-c` configuration, `--exec-path`, custom pager,
custom hooks/config paths, and unknown global or subcommand flags.

Supported families are:

- read: bounded `status`, `diff`, `log`, `show`, and `rev-parse` forms that
  disable external diff, text conversion, pagination, and user-supplied format
  execution surfaces;
- index/worktree mutation: `add`, `restore`, `checkout`, `switch`, `reset`, and
  `clean`;
- history/ref mutation: `commit`, `merge`, `rebase`, `branch`, and `tag`;
- network/publication mutation: `fetch`, `pull`, and `push`.

The parser extracts pathspecs, refs, remotes, force flags, recursive behavior,
and breadth indicators without invoking Git. Repository identity and actual ref
state come only from the resolver.

Git evidence collection uses bounded, read-only parsing of documented repository
metadata through a narrow `GitEvidenceProvider`. It does not invoke the `git`
binary, repository hooks, filters, pagers, credential helpers, aliases, or
repository-configured programs. Unsupported repository layouts or metadata
formats return `indeterminate` and require a separately reviewed extension.

### Apply-patch subset

The parser requires one bounded Begin/End Patch document and recognizes Add,
Update, Delete, and Move operations. It rejects duplicate directives, unknown
headers, missing terminators, ambiguous paths, absolute paths, traversal,
excess operations, excess content, and unsupported binary or rename forms.

Patch content remains sensitive. The output records operation type, bounded
path candidates, line-count metadata, and digests; it does not retain content
in audit-facing structures.

## Target resolution

`TargetResolver` is an OS-neutral interface implemented separately under
Windows, Linux, and macOS compilation modules. It performs read-only filesystem
and Git evidence collection. Unsupported platforms compile to a resolver that
returns typed `unsupported_platform`.

Common algorithm:

1. Validate the trusted working directory and configured repository boundary.
2. Join relative candidates lexically without environment or glob expansion.
3. Reject path length, segment count, traversal, namespace, or encoding limits.
4. Canonicalize every existing component using native APIs.
5. For a creation target, canonicalize the nearest existing parent and append
   validated missing components without claiming they already exist.
6. Collect symlink, junction, reparse, mount/volume, device, file-identity,
   case, and repository-boundary evidence appropriate to the platform.
7. Enforce target-count, directory-enumeration, link-depth, filesystem-call, and
   elapsed-time budgets.
8. Produce a canonical target plus uncertainty or return `indeterminate`.

Windows uses native reparse and volume/file identity evidence and preserves UNC,
device-namespace, alternate-data-stream, and per-directory case-sensitivity
risks. Linux uses device/inode, mount, symlink, and case-sensitive path evidence.
macOS uses device/inode, mount, symlink, Unicode normalization, and detected
volume case behavior. No adapter assumes its platform's common default.

Non-UTF-8 paths are unsupported in v1 because external contracts are UTF-8 JSON.

The resolver produces a `RevalidationFingerprint` containing canonical target
identities and relevant repository/ref evidence. Milestone 1 implements bounded
comparison and target-set-change detection. Milestone 2 binds that fingerprint
to approvals and invokes it immediately before execution.

## Built-in safety baseline

`SupportedOperationProof` is required before policy evaluation can yield a final
allow. It records the recognized grammar revision, normalized operation kind,
effect, canonical targets, reversibility, blast radius, required privilege,
environment evidence, and baseline restriction.

Baseline matrix:

| Proven class | Baseline |
| --- | --- |
| Bounded metadata/read with no external execution surface | `allow` |
| Bounded reversible repository-local edit with complete targets | `allow` |
| Recoverable or potentially destructive local mutation | `ask` |
| Security-control, privilege, cross-boundary, broad deletion, or unsafe publication | `deny` |
| Unknown, incomplete, ambiguous, timed out, or unhealthy | `indeterminate` |

Policy evaluation returns restrictions only. Final composition joins the
baseline restriction with every applicable policy restriction using
`allow < ask < deny`. `NoRestriction` means only that policy added nothing.
An absent `SupportedOperationProof` always produces `indeterminate`.

Policy activation remains an atomic immutable snapshot replacement. Invalid
supplied policy makes activation unhealthy and cannot silently omit that layer.

## Audit design

Audit construction accepts only normalized, already-redacted facts. Events
contain stable correlation IDs, digests, operation/effect categories, canonical
target identities or redacted aliases, determining rules, policy snapshot ID,
health, lifecycle state, safe rationale codes, and timestamps.

Raw commands, patch bodies, credentials, tokens, authorization headers, URLs
with credentials, environment values, and configured sensitive identifiers are
never serialized to the audit sink. Debug and Display implementations use safe
codes and bounded metadata only.

Persistence uses owner-controlled, cross-platform locked JSONL segments:

- the audit directory is explicit trusted configuration outside the repository;
- startup verifies ownership/permission expectations and rejects insecure paths;
- one process holds an exclusive lock only during bounded append/rotation work;
- records are length-bounded and newline-delimited after canonical serialization;
- size-based rotation uses atomic same-directory rename and fsync-equivalent
  durability supported by the platform adapter;
- retention deletes only fully closed segments after resolving and verifying the
  configured audit root;
- partial final records are quarantined on recovery and produce degraded health;
- lock, disk, permission, corruption, rotation, or durability failure is typed.

Audit failure makes mutations `indeterminate`. A proven read-only decision may
continue with `audit_degraded`, but doctor and the decision output must report
that active enforcement is unhealthy.

## CLI and Codex hook

`ofw` is non-interactive. It never prompts for approval.

Commands:

- `ofw assess`: reads one bounded request from stdin or an explicit file,
  requires an explicit adapter and shell dialect where applicable, and emits one
  structured JSON decision.
- `ofw policy validate`: strictly validates bounded policy files and emits their
  canonical immutable snapshot identity.
- `ofw doctor`: reports adapter coverage, policy identities, trusted-config
  provenance, platform resolver support, clock health, audit health, and hook
  registration/probe health without secrets.
- `ofw hook codex-pre-tool-use`: reads one Codex envelope from stdin and emits
  only an explicit valid JSON allow result or an exit-code-2 deny reason on
  stderr. It never relies on Codex's empty-success behavior.

Normal command output is structured JSON on stdout. Diagnostics use stderr.
Hook mode is a protocol-specific exception and follows the exact verified Codex
wire behavior. An internal `ask` or `indeterminate` maps to deny until Milestone
2 verifies an operation-bound approval. Any outer failure attempts the minimal
valid deny path; host fail-open behavior remains a documented residual risk.

Doctor's harmless-allow and synthetic-deny probes execute the installed local
hook command path, not an in-process shortcut. Missing, stale, disabled, or
mismatched registration is unhealthy.

## Trusted configuration

Trusted configuration is explicit, bounded, and located outside the untrusted
repository root. It supplies:

- shell dialect and supported host path;
- working directory and repository boundary;
- environment and optional tenant mapping;
- organization/user policy locations and repository-policy enablement;
- audit root, rotation size, retention, and mutation failure behavior;
- deadline and resource budgets within compiled maxima.

Repository policy is read as untrusted restriction-only input. It cannot select
trusted configuration, audit location, shell dialect, environment, tenant, or a
weaker failure mode.

## Resource and deadline model

Every public boundary receives a `Budget` containing a monotonic deadline and
compiled maximum counters. Callers may tighten but not expand maxima. Parsers,
resolvers, policy evaluation, canonicalization, hashing, audit construction,
locking, and CLI I/O check the budget at bounded intervals.

Deadline exhaustion is `indeterminate`. Ordinary warm-path assessment targets
p95 at or below 25 ms on each supported CI platform. Performance evidence is
reported separately from process startup and filesystem cold-cache behavior.

## Dependencies

Runtime dependencies remain minimal and purpose-specific:

- `serde` and `serde_json` for strict typed JSON;
- `sha2` for SHA-256;
- one vetted cross-platform file-locking crate for audit serialization;
- narrowly scoped Windows API bindings required for reparse, volume, identity,
  and permission evidence.

The CLI uses a small internal argument parser unless a vetted CLI dependency is
shown to reduce the trusted surface. No regex, shell parser, glob, scripting,
async runtime, network client, plugin loader, or database dependency is added.

Before modifying `Cargo.toml`, each crate is checked for exact spelling,
ownership, maintenance, licensing, feature surface, advisories, transitive
dependencies, and necessity. The earlier npm-oriented validation mismatch does
not substitute for Cargo ecosystem validation; validation evidence is recorded
before download. Default features are disabled where they expand the surface
without need, and the lockfile is committed.

## Test strategy

### Red-first evidence

Every security invariant has a retained vulnerable function, stub, mutation, or
fixture proving the assertion fails when the invariant is removed. Red-first
witnesses cover at least:

- envelope-only readiness;
- unknown syntax treated as safe;
- shell expansion or execution during parsing;
- lexical-only target containment;
- symlink/junction/reparse escape;
- target-set change ignored during revalidation;
- `NoRestriction` mapped directly to allow;
- lower-layer policy narrowing;
- audit failure ignored for mutations;
- raw secret written to audit;
- deadline exhaustion mapped to allow;
- missing hook path reported healthy.

### Deterministic tests

- Unit and table tests for every accepted command and flag combination.
- Negative and abuse corpora for injection syntax, encoding, truncation,
  duplicate keys, resource exhaustion, ambiguous paths, and secret canaries.
- Property tests for policy monotonicity, stable normalization, bound adherence,
  canonical serialization, and decision determinism.
- Concurrency tests for policy snapshot readers and audit writers.
- Platform temporary-filesystem tests for symlinks, junctions/reparse points,
  mounts/volumes available in CI, case behavior, missing creation targets, and
  repository-boundary escapes.
- End-to-end CLI tests and real installed Codex allow/deny probe tests.
- Deadline/allocation tests and warm-path benchmarks.

### Fuzzing and mutation

Every untrusted parser has a fuzz target with bounded allocation and execution
time assertions. Stable deterministic regression seeds run in the normal test
suite; scheduled fuzz jobs retain newly discovered seeds. Mutation testing
targets baseline proof, policy joining, indeterminate propagation, audit failure
handling, redaction, and revalidation comparisons.

## CI and release verification

GitHub Actions uses immutable commit identities for actions and runs:

- formatting and Clippy with warnings denied;
- unit, integration, protocol conformance, adversarial, and red-first tests;
- Windows, Linux, and macOS resolver matrices;
- schema validation and documentation checks;
- dependency review, Cargo audit, license review, and SBOM generation;
- deterministic fuzz regression and scheduled extended fuzzing;
- mutation testing on governed scheduled or release-candidate jobs;
- reproducible release builds with checksums and provenance.

Milestone 1 artifacts are development artifacts, not production enforcement
releases. Signing and verification mechanisms are exercised before Milestone 2
but no active-protection claim is permitted.

## Functional-requirement mapping

- FR-001 through FR-004: strict host adapter and versioned invocation boundary.
- FR-005 and FR-006: installed-path allow/deny doctor probes and explicit
  missing-coverage health.
- FR-010 through FR-012: native target resolution and closed non-executing
  parsing with unsupported dynamic forms.
- FR-013 and FR-014: revalidation fingerprint and target-set comparison API;
  approval binding and pre-execution invocation remain Milestone 2.
- FR-015: trusted configuration supplies environment/tenant identity.
- FR-020 through FR-028: deterministic baseline-plus-restriction orchestration
  and atomic immutable policy activation.
- FR-050 through FR-054: redacted lifecycle audit, typed audit failure, and
  structured diagnostics.

## Completion criteria

Milestone 1 is complete only when:

1. Every included functional requirement has executable passing evidence for
   the exact supported subset.
2. Every unsupported or incomplete recognized mutation is `indeterminate` and
   the Codex hook emits deny.
3. Windows, Linux, and macOS resolver matrices pass their declared support
   cases without assuming platform defaults.
4. Red-first, negative, abuse, property, fuzz regression, mutation, concurrency,
   deadline, and performance gates pass.
5. No audit/debug/error fixture leaks canary secrets or raw sensitive payloads.
6. The open `NoRestriction` advisory is resolved by executable baseline-proof
   enforcement and reviewed before orchestration is accepted.
7. Dependency, SBOM, reproducibility, compatibility, rollback, and clean-room
   provenance evidence is current.
8. README and diagnostics state that signed approvals, replay protection,
   pre-execution approval revalidation, and production enforcement remain
   Milestone 2.

## Compatibility and rollback

All external contracts remain versioned. Unknown security-critical fields and
unsupported major versions fail explicitly. Adapter protocol revisions are
independent from core contract versions.

Policy activation and trusted configuration activation are atomic. Rollback may
select only a binary supporting every active contract and policy major version.
Otherwise startup is unhealthy and mutating operations deny. Audit format
changes require a reader compatible with all retained segments or an offline,
verified migration that never feeds unredacted data back into the runtime.

Each implementation slice is independently revertible at its crate boundary.
Removing a host adapter cannot weaken the core; it changes that host path to
unsupported/unhealthy. Removing one platform resolver changes only that
platform to unsupported and cannot trigger another platform's fallback.

## Residual risks

- A host may fail open, omit hooks, or expose an unverified execution path.
- Static interpretation cannot predict arbitrary third-party program behavior;
  such commands remain unsupported.
- Filesystem state can change after assessment; Milestone 2 approval binding and
  immediate pre-execution revalidation reduce but cannot eliminate races.
- Audit failure can deny mutation availability by design.
- A privileged hostile administrator can tamper with local binaries, keys,
  configuration, or observations.
- New host, shell, Git, and filesystem behavior requires new protocol evidence
  and cannot be assumed safe from naming similarity.
