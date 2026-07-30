# Product Requirements Document: Operation Firewall

| Field | Value |
|---|---|
| Status | Draft for architecture review |
| Version | 0.1 |
| Last updated | 2026-07-30 |
| Product | Operation Firewall |
| Initial delivery | Local Codex plugin with a minimal enforcement runtime |
| Owners | To be assigned |

## 1. Executive summary

Operation Firewall is a policy-driven safety layer for AI agents that can mutate code, data, infrastructure, and external systems. It evaluates operations before execution, resolves their real targets and context, and returns one of four deterministic decisions: `allow`, `ask`, `deny`, or `indeterminate`.

The product is intentionally broader than a destructive-command denylist. It is designed to cover shell execution, direct filesystem operations, Git, databases, cloud infrastructure, Kubernetes, infrastructure-as-code, and tool or API calls through a common typed intent model.

The first release will establish the trusted enforcement core: strict protocol validation, a versioned `OperationIntent` contract, deterministic policy evaluation, target resolution, operation-bound approval, redacted audit events, and conformance tests. It will not claim complete protection and will treat unavailable enforcement, unsupported high-risk events, parser failure, timeout, and protocol drift as explicit security states.

## 2. Problem statement

AI coding agents routinely receive authority to run commands, edit files, change Git state, call APIs, and operate infrastructure. Existing controls are commonly centered on matching dangerous shell command strings. That approach is valuable as a guardrail but leaves material gaps:

- The agent host may not emit a hook for every execution path.
- Direct file-edit tools, SDKs, MCP tools, and APIs may avoid shell interception entirely.
- Unknown mutating operations may be allowed because they do not match a deny rule.
- Protocol drift or malformed events may silently disable evaluation.
- Dynamic code, scripts, wrappers, aliases, indirect input, and multiple shell dialects create a continuing parser and rule-completeness problem.
- A security gate can become difficult to audit when UI, telemetry, update, history, and policy-authoring functionality share its trusted runtime.
- Environment-variable bypasses and terminal challenges do not provide strong, operation-bound authorization.
- Repository-controlled configuration may attempt to weaken user or organization policy.

Users need a small, predictable, fail-safe decision boundary that evaluates the intended effect of an operation across tools, not merely its textual spelling.

## 3. Product vision

Enable capable AI agents to work quickly while making destructive, privileged, production, cross-tenant, security-control, and high-blast-radius operations deliberate, bounded, observable, and recoverable.

Operation Firewall should behave like a transaction firewall for agent actions:

1. Understand the proposed operation through typed facts.
2. Establish what and where it will affect.
3. Apply deterministic policy.
4. Obtain exact authorization when required.
5. Execute through the narrowest practical boundary.
6. Verify and record the outcome without exposing secrets.

## 4. Product principles

1. **Unknown does not mean safe.** Uncertainty is represented as `indeterminate` or escalated to `ask` according to trusted policy.
2. **Intent over spelling.** Equivalent effects should receive equivalent decisions across commands, APIs, and tools.
3. **Exact authorization.** Approval must be bound to the normalized operation and resolved targets.
4. **Monotonic repository policy.** A repository may add restrictions but cannot weaken user or organization policy.
5. **Deterministic enforcement.** AI may enrich evidence but cannot be the sole authorization or enforcement mechanism.
6. **Reversibility first.** Prefer preview, transaction, snapshot, quarantine, soft-delete, backup, dry-run, and lease mechanisms.
7. **Small trusted computing base.** Keep enforcement separate from UI, analytics, updates, and reporting.
8. **Secure failure.** Hook absence, schema drift, parsing failure, timeout, and unsupported high-risk actions must be observable and must not silently become clean allows.
9. **Privacy by design.** Audit useful metadata while redacting credentials, secrets, sensitive payloads, and tenant data.
10. **No perfect-security claims.** Design for prevention, containment, detection, response, and recovery.

## 5. Target users

### 5.1 Individual developers

Developers using coding agents with shell and repository access who want protection against accidental loss without constant approval fatigue.

### 5.2 Engineering teams

Teams that need consistent project and organization policy, shared protected resources, auditable exceptions, and predictable behavior across agent hosts.

### 5.3 Platform and security teams

Operators governing production infrastructure, multi-tenant data, CI/CD, secrets, identity, DNS, cloud resources, and regulated environments.

### 5.4 Agent and tool developers

Developers integrating a deterministic safety decision into new tool protocols, MCP servers, internal agents, or execution brokers.

## 6. Primary jobs to be done

- Before an agent executes an operation, determine whether it is safe, prohibited, uncertain, or requires human authorization.
- Before requesting approval, show the exact targets, environment, blast radius, reversibility, and safer alternatives.
- Prevent approval for one operation from authorizing a different target or modified payload.
- Detect when the enforcement path is missing, stale, malformed, or unable to establish required facts.
- Let organizations set mandatory policy while allowing repositories to add stricter local controls.
- Produce an audit trail sufficient to explain decisions and investigate failures without leaking sensitive information.
- Verify what actually changed and identify partial or recoverable failure states.

## 7. Scope

### 7.1 Minimum viable product

The MVP will include:

- A valid Codex plugin and behavioral guarded-operations skill.
- A standalone local enforcement core with no network dependency on the decision path.
- Strict parsing of supported pre-tool event envelopes.
- A versioned `OperationIntent` schema.
- Deterministic `allow`, `ask`, `deny`, and `indeterminate` decisions.
- Initial operation types for shell execution, filesystem mutation, and Git mutation.
- Target resolution for local paths and Git repositories.
- Policy hierarchy for organization, user, and repository restrictions.
- Operation-bound, expiring, single-use approval capabilities.
- Redacted structured audit events.
- A local diagnostic command that verifies hook registration and end-to-end enforcement.
- Unit, conformance, adversarial, property, fuzz, and integration test foundations.

### 7.2 Subsequent scope

Later releases may add:

- Database and migration adapters.
- Kubernetes, cloud, DNS, identity, secret-management, CI/CD, and infrastructure-as-code adapters.
- MCP and structured API tool adapters.
- Script and indirect-input inspection.
- Out-of-band organization approval services.
- Constrained execution workers and operating-system sandbox integrations.
- Central policy distribution, signed policy bundles, fleet health, and aggregated audit export.
- Administrative UI and reporting outside the enforcement runtime.

### 7.3 Non-goals

The first release will not attempt to provide:

- General malware detection.
- Perfect reconstruction of arbitrary runtime-generated code.
- Protection from a fully privileged hostile operating-system administrator.
- A claim that every host execution path is intercepted.
- A general endpoint detection and response platform.
- Autonomous policy generation or autonomous approval by an AI model.
- A fork, translation, or derivative implementation of `destructive_command_guard`.

## 8. Core domain model

### 8.1 OperationIntent v1

Every supported adapter must produce a versioned intent containing at least:

| Field | Purpose |
|---|---|
| `schema_version` | Enables strict compatibility and migration behavior. |
| `operation_id` | Unique identifier for correlation and replay protection. |
| `timestamp` | Records when the operation was proposed. |
| `actor` | Identifies the agent, user, host, and process context. |
| `session` | Binds decisions and approval to an agent session. |
| `source` | Identifies the host, tool, protocol, and adapter version. |
| `operation_kind` | Typed effect such as execute, delete, overwrite, move, force-push, or permission change. |
| `raw_request_digest` | Integrity binding without retaining sensitive raw content. |
| `normalized_operation` | Canonical representation used for policy and approval binding. |
| `targets` | Resolved resources including path, repository, ref, tenant, project, or remote resource identifiers. |
| `working_context` | Working directory, repository root, environment, tenant, and platform. |
| `requested_privileges` | Effective identity, elevation, credentials, or scopes required. |
| `reversibility` | Reversible, recoverable, conditionally recoverable, or irreversible. |
| `blast_radius` | Bounded estimate with the evidence supporting it. |
| `preconditions` | Facts that must remain true before execution. |
| `evidence` | Read-only facts used to resolve and classify the operation. |
| `sensitive_fields` | Redaction metadata; never a copy of secret values. |

Adapters must reject unknown required fields only when strict compatibility demands it, preserve safe forward-compatibility metadata where designed, and never guess security-critical fields.

### 8.2 Decision model

Every evaluation returns:

- Decision: `allow`, `ask`, `deny`, or `indeterminate`.
- Stable rule and policy identifiers.
- Severity and risk categories.
- Human-readable rationale.
- Facts and policy layers that determined the result.
- Safer alternatives when applicable.
- Approval requirements when the decision is `ask`.
- Expiry and re-evaluation requirements.

Decision meanings:

| Decision | Meaning |
|---|---|
| `allow` | The supported operation is sufficiently proven safe under all active policy layers. |
| `ask` | Execution requires an authorization capability bound to this exact operation. |
| `deny` | Active trusted policy prohibits the operation. |
| `indeterminate` | Required facts could not be established or evaluation did not safely complete. |

`indeterminate` is never internally converted to a clean `allow`. A trusted policy may map it to `ask` or `deny` for a specific integration.

## 9. Functional requirements

### 9.1 Protocol and adapter requirements

- **FR-001:** The system must validate event size, structure, version, tool identity, and required fields before evaluation.
- **FR-002:** Every recognized supported event must produce a decision or an explicit integration error; it must not disappear through an empty return path.
- **FR-003:** A recognized mutating event with an unextractable operation must produce `indeterminate`.
- **FR-004:** Adapters must identify their exact version and supported protocol range.
- **FR-005:** The diagnostic command must exercise a harmless allow probe and a synthetic deny probe through the real installed hook path.
- **FR-006:** Missing hook coverage must be reported as an unhealthy enforcement state rather than inferred as safe.

### 9.2 Target-resolution requirements

- **FR-010:** Local filesystem targets must be resolved against an explicit working directory.
- **FR-011:** Resolution must detect traversal, symlinks, junctions, reparse points, mount boundaries, and case-normalization risks appropriate to the platform.
- **FR-012:** Globs, variables, aliases, and dynamic targets must be expanded only through bounded, non-executing mechanisms.
- **FR-013:** The resolved targets used for approval must be revalidated immediately before execution.
- **FR-014:** A target-set change after approval must invalidate the approval.
- **FR-015:** Tenant, production, and remote-resource identity must come from trusted context or independently verified evidence, not solely agent-supplied labels.

### 9.3 Policy requirements

- **FR-020:** Policy evaluation must be deterministic for the same normalized intent and policy bundle.
- **FR-021:** Organization policy must take precedence over user and repository policy.
- **FR-022:** Repository policy may add `ask` or `deny` decisions but may not weaken a higher-level result.
- **FR-023:** Policy must distinguish known read-only actions, bounded reversible mutations, destructive mutations, security-control changes, privilege changes, and possible data egress.
- **FR-024:** Unknown high-risk operation kinds must not default to `allow`.
- **FR-025:** Policy syntax must not permit arbitrary executable code or unbounded evaluation.
- **FR-026:** Policy bundles must be versioned, validated before activation, and identified in every audit decision.

### 9.4 Approval requirements

- **FR-030:** An approval must be cryptographically bound to the normalized operation digest, resolved targets, actor, session, environment, policy decision, expiry, and permitted use count.
- **FR-031:** Approval capabilities must be short-lived and single-use by default.
- **FR-032:** Approval replay, payload substitution, target substitution, cross-session use, and environment substitution must fail closed.
- **FR-033:** Generic confirmation, environment variables, displayed terminal codes, or model-generated acknowledgement must not be treated as sufficient authorization.
- **FR-034:** The approval message must present the destructive effect, exact targets, blast radius, reversibility, and safer alternatives in plain language.
- **FR-035:** Organization policy may require an out-of-band approver distinct from the requesting agent or operator.

### 9.5 Execution and verification requirements

- **FR-040:** The system must prefer non-destructive alternatives when they satisfy the stated objective.
- **FR-041:** Execution must use the least privilege and narrowest available resource scope.
- **FR-042:** Operations must define timeout, retry, idempotency, and concurrency behavior before execution when those concerns apply.
- **FR-043:** Partial failure must be represented explicitly and must include recovery guidance where available.
- **FR-044:** Postcondition checks must verify the actual result for supported operation types.
- **FR-045:** An approval must not authorize an internally rewritten or expanded operation unless the rewritten form has the same bound digest and target set.

### 9.6 Audit and diagnostics requirements

- **FR-050:** Every non-trivial decision must emit a structured audit event with correlation identifiers.
- **FR-051:** Audit output must redact secrets, credentials, authorization headers, sensitive payload bodies, and configured sensitive paths or identifiers.
- **FR-052:** Audit events must distinguish proposed, evaluated, approved, denied, executed, failed, partially completed, and verified states.
- **FR-053:** Audit failure must be observable and its enforcement effect explicitly controlled by trusted policy.
- **FR-054:** Diagnostics must report adapter coverage, active policy identities, configuration provenance, clock health, approval-key health, and audit health without exposing secrets.

## 10. Risk classification

The MVP must support these risk dimensions without reducing them to one opaque score:

- Data loss or overwrite.
- Scope and number of affected targets.
- Reversibility and recovery time.
- Local, remote, shared, production, or cross-tenant impact.
- Privilege and credential scope.
- Security-control modification.
- Data disclosure or egress potential.
- Availability and service interruption.
- Uncertainty in parsing, target resolution, or indirect execution.

Policy may use bands such as low, moderate, high, and critical, but the underlying dimensions and evidence must remain visible.

## 11. Security and privacy requirements

- The enforcement core must not depend on a network service for ordinary local decisions.
- Inputs must have explicit size, nesting, recursion, allocation, and evaluation-time limits.
- Parser and policy failures must be contained and returned as typed errors or `indeterminate` decisions.
- Secrets must use operating-system or approved secret storage and must never be stored in policy files or audit logs.
- Approval signing keys must be separated from agent-writable repository state.
- Repository configuration and content must be treated as untrusted input.
- Multi-tenant adapters must enforce tenant identity in authorization, caching, audit, and approval binding.
- The system must support key rotation and rejection of revoked or expired approval keys.
- Release artifacts must be reproducible where practical, signed, checksummed, and accompanied by an SBOM and provenance.
- CI actions and build tools must be pinned to immutable versions or commit identities; unverified remote scripts must not execute in CI.

## 12. Reliability and performance requirements

- The decision engine must have no unbounded parser or policy path.
- A deadline overrun must produce `indeterminate`, never `allow`.
- The local enforcement core must remain operational when optional UI, telemetry, update, or reporting components are unavailable.
- The MVP warm decision target is p95 at or below 25 ms for ordinary local operations on supported development hardware; process-start overhead must be measured separately.
- The system must avoid duplicate execution during host retries through operation identifiers and idempotency controls.
- Crash recovery must preserve approval replay protection and audit consistency.

Performance targets are acceptance goals, not permission to skip required analysis. If required facts cannot be established within budget, the result is `indeterminate`.

## 13. User experience requirements

- Allow decisions should normally be silent or minimally visible.
- Ask and deny responses must lead with the effect and target, followed by rationale and a safer alternative.
- Messages must distinguish policy denial from incomplete analysis or integration failure.
- Approval requests must avoid dumping raw commands or payloads containing secrets.
- The user must be able to inspect why a rule matched and which policy layer supplied it.
- Repeated low-risk prompts must be addressed through better deterministic policy, not broad bypasses.

## 14. Architecture constraints

- The enforcement core must be a standalone, testable module with a narrow public interface.
- Protocol adapters must be isolated from policy evaluation.
- Target resolvers must be platform-specific behind typed interfaces where operating-system behavior differs.
- Approval verification must be independent from presentation and terminal input.
- Audit persistence must be isolated from policy evaluation and must accept already-redacted events.
- UI, policy authoring, analytics, update checks, fleet management, and dashboards must not run inside the trusted hook hot path.
- The implementation language and dependency set remain open decisions, but stable tooling, memory safety, cross-platform support, startup performance, and supply-chain footprint are mandatory evaluation criteria.

## 15. Clean-room and provenance requirements

- Implementation must be independently designed from this PRD, the repository threat model, and original test cases created for this project.
- Contributors must not copy, translate, mechanically transform, or adapt code, patterns, tests, documentation, rule data, or internal structure from `destructive_command_guard`.
- External examples, specifications, and datasets must have recorded source, license, and permitted use.
- A provenance record must accompany imported test fixtures and policy data.
- The project license must be selected before public distribution.
- Legal review is required before using materials whose terms restrict relevant parties or derivative use.

## 16. Success metrics

### 16.1 Release acceptance metrics

- 100% of supported protocol fixtures yield an explicit typed outcome.
- Zero clean allows for malformed recognized mutating events in the conformance suite.
- Zero approval replay, target-substitution, cross-session, or expired-token successes in the security suite.
- Zero critical false negatives in the release-blocking critical-operation corpus.
- All parsers and resolvers meet established complexity and memory budgets under fuzz and adversarial inputs.
- No secrets appear in audit-redaction fixtures or captured integration logs.
- Plugin, skill, policy schemas, and release artifacts pass their validators.

### 16.2 Operational metrics

- Hook coverage health by host, version, tool type, and execution path.
- Decision volume by outcome and risk category.
- `indeterminate` rate and root cause.
- Ask-to-approve, ask-to-deny, and approval-expiry rates.
- Policy override and repeated-prompt rate.
- Decision latency and deadline exhaustion rate.
- Postcondition failure and partial-completion rate.

Operational metrics must use redacted, privacy-preserving dimensions and must be opt-in where required.

## 17. Milestones

### Milestone 0: Foundation and decisions

Deliverables:

- Approved PRD and threat model.
- Architecture decision for implementation language and workspace structure.
- Project license decision.
- `OperationIntent` v1 JSON Schema or equivalent typed schema.
- Decision, error, policy, and audit contracts.
- Clean-room provenance process.

Exit criteria:

- Schemas validate positive and negative fixtures.
- Trust boundaries and unsupported states are documented.
- No production enforcement claim is made.

### Milestone 1: Local decision core

Deliverables:

- Strict event-envelope parser.
- Shell, filesystem, and Git intent adapters for an explicitly documented subset.
- Local target resolution.
- Deterministic policy engine and monotonic policy merging.
- Redacted audit event generation.
- CLI assessment and policy-validation commands.

Exit criteria:

- Required functional tests for FR-001 through FR-026 and FR-050 through FR-054 pass for the supported subset.
- Fuzzing shows bounded behavior under the established budgets.
- Unsupported or incomplete high-risk operations return `indeterminate`.

### Milestone 2: Bound approval and real hook integration

Deliverables:

- Approval capability creation and verification.
- Replay protection and key management.
- Codex pre-tool hook adapter.
- End-to-end doctor command and integration health reporting.
- Pre-execution target revalidation and postcondition checks.

Exit criteria:

- FR-030 through FR-045 pass end to end.
- Host/version coverage is documented and machine-verifiable.
- Known missing host paths are reported as unhealthy rather than silently presented as protected.

### Milestone 3: Broader operation adapters

Deliverables:

- Prioritized database, Kubernetes, cloud, IaC, and MCP adapters.
- Signed policy bundles and organization policy support.
- Optional out-of-band approval integration.

Exit criteria:

- Every adapter ships with a protocol contract, threat analysis, critical corpus, recovery behavior, and operational metrics.

## 18. MVP acceptance scenarios

The MVP must demonstrate at least these behaviors:

1. A read-only repository status operation is allowed with minimal output.
2. A destructive Git operation against uncommitted work returns `ask` or `deny` with exact repository and ref context.
3. A recursive deletion request resolves its concrete targets and rejects an unresolved or escaping path.
4. A recognized shell event missing its command field returns `indeterminate`.
5. A malformed, oversized, deeply nested, or deadline-exhausting event never becomes a clean allow.
6. Repository policy can protect an additional path but cannot allow an organization-denied operation.
7. Approval for one path cannot be replayed for another path or session.
8. A symlink or junction target change after approval invalidates execution.
9. Audit output explains the decision while redacting embedded credentials and sensitive values.
10. Disabling or removing the hook causes the diagnostic command to report the enforcement path as unhealthy.

## 19. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Host does not emit events for every operation | Maintain explicit coverage probes; report missing paths as unhealthy; add adapters or constrained execution where possible. |
| False positives cause users to disable protection | Use typed context, reversible alternatives, explainable policy, scoped approvals, and override telemetry. |
| False negatives from unknown tools or effects | Use `indeterminate` for unsupported high-risk actions and expand typed adapters based on prioritized evidence. |
| Parser complexity creates denial-of-service or bypass | Use bounded parsers, small modules, fuzzing, property tests, complexity budgets, and hard deadlines. |
| Agent alters hooks, policy, or approval state | Separate trusted state from repository state, use integrity checks, least privilege, signed policy, and external health probes. |
| Approval fatigue weakens judgment | Improve deterministic low-risk policy and require approval only for materially risky operations. |
| Audit leaks sensitive information | Redact before persistence, test with canary secrets, minimize retained fields, and apply retention controls. |
| Supply-chain compromise affects the gate | Minimize dependencies, pin builds, produce SBOM/provenance, sign artifacts, and separate updating from enforcement. |
| Clean-room boundary is accidentally crossed | Maintain contributor rules, provenance records, independent tests, and legal review before distribution. |

## 20. Open decisions

The following decisions must be resolved during Milestone 0:

1. Enforcement-core implementation language and build system.
2. Exact Codex hook protocols and execution paths available to the first integration.
3. `OperationIntent` serialization format and schema-evolution rules.
4. Policy authoring format and signed-bundle format.
5. Approval key storage and local human-authorization UX.
6. Audit persistence format, retention, and rotation.
7. Cross-platform path-resolution strategy and initial supported operating systems.
8. Project license and contributor provenance process.
9. Whether the first execution boundary only advises/blocks or also brokers constrained execution.
10. Minimum host behavior required before the product may report that enforcement is active.

## 21. Definition of done for the first production release

The first production release is complete only when:

- Its supported operation and host coverage is explicit and machine-verifiable.
- Every supported event produces a typed result.
- Indeterminate and integration-failure behavior is fail-safe under active trusted policy.
- Operation-bound approval and replay protection pass adversarial testing.
- Policy precedence and repository monotonicity are proven by tests.
- Target resolution and revalidation pass cross-platform containment tests for supported platforms.
- Audit redaction passes canary-secret tests.
- Performance and resource budgets pass on supported platforms.
- Release artifacts are signed, checksummed, accompanied by provenance and an SBOM, and independently verifiable.
- Installation, upgrade, rollback, hook-health, and recovery paths are documented and tested.
- Security limitations are documented without claims of complete protection.

