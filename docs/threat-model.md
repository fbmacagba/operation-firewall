# Threat Model

Status: Approved for Milestone 0

## Protected assets

- Source code, uncommitted work, build outputs, and local developer state.
- Local and remote Git history, refs, releases, and repository integrity.
- Filesystems, databases, backups, tenant data, and production data.
- Cloud, Kubernetes, CI/CD, DNS, identity, secret-management, and external API resources.
- Safety configuration, hook registration, policy bundles, approval keys/state, audit trails, and coverage health.
- Availability of developer and production workflows.

## Threat actors and failure modes

- A well-intentioned but mistaken agent or operator.
- Prompt injection influencing an agent, command, tool call, or approval presentation.
- A malicious repository, dependency, fixture, policy file, symlink, hook, or script.
- A compromised or schema-drifting host integration.
- Ambiguous paths, aliases, wrappers, dynamic code, globs, variables, symlinks, junctions, reparse points, and mounts.
- Concurrent agents racing policy activation, approval redemption, audit persistence, or target mutation.
- Partial failure, retry, timeout, stale evidence, stale authorization, replay, and clock error.
- An operator approving a broader operation than intended or being shown misleading/redacted context.
- A compromised dependency, build worker, release channel, or signing identity.

## Trust zones

1. **Host/repository zone (untrusted):** host envelopes, tool inputs, repository content, repository policy, working-directory state, and agent-provided labels.
2. **Enforcement zone (trusted and minimal):** strict validation, normalization, resolution, immutable policy evaluation, approval verification, and pre-persistence redaction.
3. **User/organization control zone (trusted by configured authority):** higher-level policy, approval keys, replay state, trusted environment/tenant mapping, and activation controls. It must not be writable by the repository or agent identity.
4. **Observation zone (less trusted):** audit storage, diagnostics, coverage reconciliation, UI, analytics, and reporting. Compromise here must not grant execution authority.
5. **Host execution zone (outside product control):** Codex or another host executes after an allow. Host fail-open behavior and missing interception paths are residual risks that must be measured and disclosed.

## Security invariants

1. Unknown does not equal safe.
2. Approval for one normalized operation, target set, actor, session, environment, or policy snapshot cannot authorize another.
3. Repository-controlled configuration cannot weaken, delete, shadow, replace, reorder, or waive a user or organization restriction.
4. High-risk targets are resolved before approval and revalidated before execution.
5. An indeterminate high-risk decision cannot silently become allow inside an Operation Firewall adapter.
6. Audit failure cannot leak secrets; its enforcement effect is explicit and observable.
7. No adapter infers tenant, production, remote-resource, or privilege scope solely from agent-supplied labels.
8. Capability verification has no non-cryptographic fallback, and single-use redemption is atomic.
9. Policy activation is atomic; readers never observe a partially merged snapshot.
10. A security test is not accepted as evidence until it has demonstrated failure against the vulnerability it claims to detect.

## Abuse cases

- A repository supplies an empty rule list, duplicate rule ID, deletion marker, or lower-severity action to erase an organization deny.
- A malformed repository policy attempts to make the engine discard all policy and continue.
- A tool payload uses an unsupported operation kind or schema extension to reach an allow path.
- A target changes through a symlink, junction, ref update, rename, or mount transition after approval.
- Two workers redeem one approval concurrently or replay it after a crash.
- A secret is embedded in a command, URL, header, environment variable, path, rationale, or tool payload and reaches audit output.
- The hook crashes, times out, emits malformed output, or is removed; the Codex host proceeds because its hook failure mode is fail-open.
- A warn-only rollout or stale binary is represented as active blocking protection.

## Security-state treatment

Malformed input, unsupported security-critical versions, policy activation failure, parser/resolver timeout, unavailable required evidence, approval-state failure, audit-health failure, and missing coverage are explicit typed states. The Codex adapter must translate recognized high-risk `indeterminate` states to its supported deny wire response. An independent monitor detects missing hook decisions because the failed hook cannot reliably report its own absence.

## Residual risks

- Codex controls hook execution and fails open for several hook failures; Operation Firewall cannot guarantee interception from inside that hook.
- Correctly classified and approved third-party programs may have effects that cannot be predicted or fully verified.
- A fully privileged hostile operating-system administrator can tamper with binaries, keys, process state, or observations.
- Availability can be denied by malformed repository policy because v1 chooses fail-safe atomic activation over silently ignoring the layer.
- Human approval can still be mistaken even when accurately bound and presented.
- Novel operation encodings and host paths may remain unsupported until adapters and coverage probes are added.

## Out of scope for the first release

- General malware detection.
- Protection against a fully privileged hostile operating-system administrator.
- Correctness of arbitrary third-party programs after they pass the execution boundary.
- Perfect reconstruction of dynamically generated code.
- A claim that every host execution path is intercepted.
