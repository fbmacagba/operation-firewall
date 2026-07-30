# Architecture

## Decision pipeline

```text
Tool event
  -> protocol adapter
  -> strict envelope validation
  -> typed OperationIntent
  -> target and environment resolver
  -> deterministic policy engine
  -> ALLOW | ASK | DENY | INDETERMINATE
  -> approval verifier when required
  -> constrained execution
  -> postcondition verification
  -> redacted audit event
```

## Core components

### Protocol adapters

Adapters translate host-specific events into one versioned schema. A recognized mutating event that cannot be translated must not become a clean allow.

### Operation intent

The planned schema includes actor, session, operation kind, arguments, resolved targets, working directory, environment class, tenant, reversibility, estimated blast radius, evidence, and requested privileges.

### Policy engine

The engine is deterministic. Policies evaluate typed facts and return a decision, stable rule identifier, severity, rationale, safer alternatives, and approval requirements.

### Approval verifier

Approvals are short-lived signed capabilities bound to an operation digest. Terminal CAPTCHAs and environment-variable bypasses are not authorization mechanisms.

### Execution boundary

Execution should use least privilege, target containment, resource limits, timeouts, idempotency controls, and transactional or recoverable mechanisms where available.

## Trusted computing base

Only envelope validation, normalization, target resolution, policy evaluation, approval verification, and audit emission belong in the enforcement runtime. TUI, dashboards, updates, analytics, and policy authoring tools must remain separate.

