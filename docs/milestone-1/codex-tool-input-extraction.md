# Codex `Bash` and `apply_patch` tool-input extraction

Status: implementation contract for the Milestone 1 extraction slice

## Threat and invariants

Although the outer hook envelope is valid, its `tool_input` remains untrusted.
An attacker or drifting host may omit the mutation, change its type, add fields
with ambiguous semantics, duplicate an accepted field through JSON escaping, or
use command text intended to trigger shell, environment, filesystem, or Git
interpretation during validation.

This slice enforces three invariants:

> A recognized `Bash` or `apply_patch` call is extracted only when
> `tool_input` is exactly the supported bounded shape. Missing, malformed,
> duplicated, unknown, empty, or oversized input is typed `indeterminate`.

> Extraction preserves the decoded command literally. It does not execute,
> expand, tokenize, evaluate, normalize paths, inspect the filesystem, or infer
> shell, Git, or patch effects.

> A valid envelope and an extracted tool input are not proof that the operation
> is supported or safe. This slice has no policy-ready or allow state.

The design is independently derived from Operation Firewall's threat model and
the public Codex hook facts recorded as `source.codex-hooks-2026-07-30`. The
prohibited comparison project was not used.

## Exact supported subset

The already-validated envelope must name `Bash` or `apply_patch`. For both tool
names, `tool_input` must be a JSON object containing exactly one member:

```json
{
  "command": "non-blank string"
}
```

The decoded `command` is limited to 65,536 UTF-8 bytes, matching the existing
bounded JSON-string budget. Leading and trailing whitespace are preserved, but
a value containing only Unicode whitespace is rejected because it does not
carry an extractable operation.

Successful extraction produces a tool-specific wrapper:

- `BashToolInput`, exposing the literal command only to the future shell-intent
  adapter through a narrow typed accessor.
- `ApplyPatchToolInput`, exposing the literal patch command only to the future
  filesystem-intent adapter through a narrow typed accessor.

Neither wrapper implements interpretation or authorization. Their `Debug`
representations report only byte length and do not expose command contents.

## Unsupported and indeterminate forms

The following are explicitly unsupported:

- an empty object or a missing `command` member;
- a `null`, boolean, number, array, object, or other non-string `command`;
- an empty or Unicode-whitespace-only command;
- any additional member, including `description`, `cwd`, `timeout`, shell
  selection, environment, or future protocol fields;
- duplicate decoded member names, including escaped spellings that decode to
  `command`;
- a decoded command longer than 65,536 UTF-8 bytes;
- any malformed, truncated, oversized, over-nested, or over-budget JSON already
  rejected by the envelope parser.

All such inputs remain typed `indeterminate`. Duplicate and generic JSON budget
failures are detected during the envelope's bounded grammar pass; strict
field-shape failures are detected during extraction. Both remain distinguishable
in the combined adapter assessment without exposing payload data.

## Boundary and compatibility

The extraction entry point accepts only a `PreToolUseEnvelope` produced by the
strict envelope parser, so callers cannot bypass envelope validation. A combined
assessment is provided for callers that need one fail-safe parser-to-extraction
boundary. Its only success state is `Extracted`, deliberately not `Ready`,
`Allowed`, or a policy outcome.

Shell parsing, patch grammar validation, path resolution, filesystem queries,
Git interpretation, operation normalization, policy evaluation, and mapping to
a host response remain later slices behind separate typed interfaces. In
particular, no `PolicyOutcome::NoRestriction` value is created or mapped here.

A Codex payload change requires a new reviewed adapter revision or an explicit
extension to this exact subset. Rollback removes the extraction API and this
document while retaining the independently useful envelope parser.
