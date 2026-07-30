---
name: guarded-operations
description: Assess and safely execute destructive, irreversible, privileged, production, tenant-data, infrastructure, or broadly mutating operations across shell, filesystem, Git, databases, cloud, Kubernetes, IaC, and tool APIs.
---

# Guarded Operations

Use this workflow before any operation that may delete, overwrite, irreversibly mutate, expose, publish, revoke, terminate, rotate, migrate, or broadly affect data or infrastructure.

## Required workflow

1. Identify the exact objective and the least-impact operation that achieves it.
2. Resolve concrete targets, environment, tenant, working directory, and privilege boundary using read-only evidence.
3. Classify reversibility and blast radius. Treat unresolved variables, globs, aliases, symlinks, junctions, dynamic code, and remote context as uncertainty.
4. Prefer preview, transaction, snapshot, quarantine, backup, soft-delete, lease, or dry-run mechanisms.
5. Require explicit user authorization when the action is destructive, irreversible, production-affecting, cross-tenant, security-control-changing, or materially broader than the stated request.
6. Bind authorization to the exact operation and targets. Never treat a generic confirmation as permission for an expanded action.
7. Execute with least privilege, bounded scope, timeouts, rate limits, idempotency protection, and retry safety.
8. Verify postconditions and report what changed, what was not changed, recovery options, and any incomplete state.

## Mandatory stop conditions

Stop and request direction when exact targets cannot be resolved, rollback is unavailable for material data, tenant or production scope is ambiguous, authorization does not match the action, or the enforcement path is unavailable.

## Prohibited shortcuts

- Do not disable hooks, policy, auditing, or security controls to make an operation pass.
- Do not use an environment-variable bypass or terminal challenge as proof of human authorization.
- Do not hide destructive behavior inside scripts, interpreters, subshells, APIs, or indirect tool calls.
- Do not claim an operation is safe solely because it fails to match a denylist.

This skill is an advisory workflow. Runtime enforcement must come from validated hooks and the policy engine; the skill alone is not a security boundary.
