# Codex `PreToolUse` envelope subset

Status: implemented envelope parser slice for Milestone 1

## Threat and invariant

The host envelope is untrusted and may be malformed, oversized, deeply nested,
duplicated, schema-drifted, or crafted to exhaust parser resources. The
invariant for this slice is:

> A malformed or unsupported recognized envelope produces a typed
> `indeterminate` state and is never ready for policy evaluation or execution.

This parser is independently designed from Operation Firewall's PRD, threat
model, and the public hook facts recorded in
`source.codex-hooks-2026-07-30`. It does not use the prohibited comparison
project.

## Supported protocol revision

Codex does not currently provide a schema-version field in the hook envelope.
The adapter therefore names the exact observed input shape
`codex.pre_tool_use/2026-07-30` and output contract version `1.0`.

The root must be one UTF-8 JSON object with exactly these fields:

- `session_id`: non-empty string
- `transcript_path`: non-empty string or `null`
- `cwd`: non-empty string
- `hook_event_name`: exactly `PreToolUse`
- `model`: non-empty string
- `turn_id`: non-empty string
- `permission_mode`: non-empty string
- `tool_name`: exactly `Bash` or `apply_patch`
- `tool_use_id`: non-empty string
- `tool_input`: JSON object

Unknown and duplicate fields are rejected. `PostToolUse`, `Stop`, other tools,
non-object tool input, and any future envelope field are unsupported protocol
states until a separately tested adapter revision accepts them. In particular,
an injected `schema_version` field is not silently ignored.

This slice validates only the outer envelope and JSON grammar. The separate
[`Bash` and `apply_patch` extraction slice](codex-tool-input-extraction.md)
strictly types the supported payload shape, but neither slice interprets shell,
filesystem, or Git intent, resolves targets, evaluates policy, constructs a
host response, or claims active enforcement.

## Resource limits

| Resource | Limit |
| --- | ---: |
| Envelope bytes | 256 KiB |
| JSON container nesting | 32 |
| JSON values | 4,096 |
| Object members | 1,024 |
| Array elements | 4,096 |
| Generic decoded JSON string | 64 KiB |
| Identifier-like envelope field | 256 bytes |
| Path-like envelope field | 4,096 bytes |

Limits are checked during a single bounded recursive-descent pass. Duplicate
keys are rejected at every object depth. Strings validate JSON escapes,
including paired UTF-16 surrogate escapes. Numbers use the JSON number grammar
and reject leading zeroes or incomplete fractions/exponents.

The parser retains bounded raw `tool_input` JSON for strict typed extraction but
deliberately omits a public raw-value accessor and uses a redacted `Debug`
representation. Parse errors contain stable categories and static safe messages
only; they do not echo field names, values, paths, commands, or payloads.

## Compatibility and rollback

Compatibility is intentionally strict. A Codex protocol change makes this
adapter return `UnsupportedProtocol`, `UnknownField`, or another typed parser
error until tests and this document are updated. A future adapter revision may
add optional fields only after their absence preserves security meaning and
their resource bounds are explicit.

Rollback removes this crate from the workspace without changing the existing
contracts or policy engine. No runtime integration depends on it yet.
