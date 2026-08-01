# AGENTS.md

## Mission

Build Operation Firewall as a production-grade, clean-room safety boundary for AI-agent operations.

## Non-negotiable rules

1. Do not copy or derive implementation, patterns, tests, or documentation from `destructive_command_guard`.
2. Do not claim complete protection, perfect detection, or immunity from bypass.
3. Treat hook absence, schema drift, parser failure, timeout, and unsupported high-risk operations as explicit security states.
4. Keep policy decisions deterministic and explainable. AI models may assist classification but must not be the sole authorization control.
5. Bind approvals to the exact normalized operation, resolved targets, actor/session, environment, expiry, and use count.
6. Never log secrets, raw credentials, authorization headers, or sensitive payload bodies.
7. Enforce tenant and environment boundaries in every adapter, cache, audit event, and approval.
8. Prefer small modules and a minimal enforcement runtime. Keep UI, analytics, updates, and reporting outside the trusted hot path.

## Engineering workflow

- Start from a written threat, invariant, or user story.
- Add negative and abuse-case tests with every policy rule.
- Bound input size, nesting, allocation, recursion, and evaluation time.
- Use typed schemas and strict validation at trust boundaries.
- Preserve auditability without exposing sensitive data.
- Document rollback and compatibility implications.

## Dependency policy

Minimize dependencies. Before any npm or pip installation, run:

```powershell
node "C:\Users\fbmac\atlas\Codex\.codex_state\user_home\scripts\validate-packages.cjs" <package-name>
```

Abort the installation if the validator exits with code 1.

## Required quality gates

The exact toolchain is not selected yet. Once selected, CI must include formatting, linting, unit tests, protocol conformance tests, adversarial tests, fuzzing, dependency review, and reproducible release verification.

<!-- graphite:managed version=12 -->
## Shared Graphite Instructions

Graphite-first is required in this repo. Follow `GRAPHITE.md` before making non-trivial code changes: for cross-file questions (who-calls, where-defined, impact, data flow, structure) run the Graphite commands first; grep/glob are for literal text and filename lookups only. Fall back to manual search only after a Graphite answer proved insufficient, and say so. Use the existing `graph-out/graph.json` as the shared project graph, and do not edit `graph-out/` manually.

**Stay inside this repository.** Do not read, write, or run commands in any other repo, including its graph. Findings about another repo go to its agent as a recommendation through the shared `.agent-channel/` (see its `PROTOCOL.md`); that agent decides and acts. A tool doing its designed job is a separate question from an agent's boundary. See `GRAPHITE.md` section "Repository Isolation".
<!-- graphite:managed-end -->
