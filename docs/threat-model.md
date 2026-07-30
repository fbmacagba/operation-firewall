# Threat Model

## Protected assets

- Source code and uncommitted work.
- Local and remote Git history.
- Filesystems and backups.
- Tenant and production data.
- Cloud, Kubernetes, CI/CD, DNS, identity, and secret-management resources.
- Safety configuration, hooks, audit trails, and approval state.

## Threat actors and failure modes

- A well-intentioned but mistaken agent.
- Prompt injection influencing an agent or tool call.
- A malicious repository or dependency.
- Protocol drift or host integration failure.
- Ambiguous paths, symlinks, junctions, aliases, wrappers, and dynamic code.
- Partial failure, retry, concurrency, timeout, or stale authorization.
- An operator accidentally approving a broader operation than intended.

## Security invariants

1. Unknown does not equal safe.
2. Approval for one operation cannot authorize another.
3. Repository-controlled configuration cannot weaken user or organization policy.
4. High-risk targets are resolved before approval and revalidated before execution.
5. An indeterminate high-risk decision cannot silently become allow.
6. Audit failure cannot leak secrets; enforcement behavior must be explicitly configured and observable.
7. No adapter may infer tenant or production scope solely from agent-supplied labels.

## Out of scope for the first release

- General malware detection.
- Protection against a fully privileged hostile operating-system administrator.
- Correctness of arbitrary third-party programs after they pass the execution boundary.
- Perfect reconstruction of dynamically generated code.

