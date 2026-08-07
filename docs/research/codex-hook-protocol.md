# Research: Codex `PreToolUse`/`PostToolUse`/`Stop` hook protocol

Status: informational research, not a design decision. Feeds PRD.md §20 open
decision #2 ("Exact Codex hook protocols and execution paths available to the
first integration").

Sources: official docs at `developers.openai.com/codex/hooks` (redirects to
`learn.chatgpt.com/docs/hooks`, re-checked 2026-08-01), corroborated against local examples of
shipped Codex plugins with `hooks.json` (figma, replayio) and the
`.codex-plugin/plugin.json` spec bundled with this machine's Codex install.
No Codex source was read to derive this — findings come from the published
docs page and observed third-party plugin configs, not from decompiling or
reading `openai/codex` source.

## Hook registration (`hooks.json`)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "...", "timeout": 30 }
        ]
      }
    ]
  }
}
```

- `matcher` is a regex over `tool_name` (e.g. `Bash`, `^apply_patch$`,
  `Edit|Write`, `mcp__filesystem__.*`). Omit or use `"*"` to match everything.
- The manifest at `.codex-plugin/plugin.json` points to this file via
  `"hooks": "./hooks/hooks.json"` (path is a plugin-relative convention, not
  a fixed name — confirm the exact relative path this project uses once the
  `hooks/` directory has real content).
- `$PLUGIN_ROOT` / `$PLUGIN_DATA` env vars are available inside the command
  string for locating the plugin's own files.

## `PreToolUse`: the only pre-execution interception point

- Fires before tool execution and is the only event that can block a call
  outright.
- Intercepts: `Bash` (shell), `apply_patch` (file edits — matcher aliases
  `Edit`/`Write`), `mcp__namespace__toolname` (MCP tool calls), and local
  function tools (e.g. `spawn_agent`, matcher `Agent`).
- Does **not** intercept hosted tools like `WebSearch`.
- Default timeout: 600s. The hook process is spawned synchronously per call;
  Codex waits for it to exit.

### stdin shape

```json
{
  "session_id": "string",
  "transcript_path": "string | null",
  "cwd": "string",
  "hook_event_name": "PreToolUse",
  "model": "string",
  "turn_id": "string",
  "permission_mode": "string",
  "tool_name": "string",
  "tool_use_id": "string",
  "tool_input": "JSON value"
}
```

For `Bash` and `apply_patch`, the current official event table specifies a
string `tool_input.command` field. For MCP tools, `tool_input` is the tool's
own argument object. Operation Firewall's implemented adapter subset accepts
only the exact command-only object documented in
[`docs/milestone-1/codex-tool-input-extraction.md`](../milestone-1/codex-tool-input-extraction.md).

### stdout shape — decision values

Only two decisions exist on the wire:

- **`allow`** (optionally with `updatedInput` to rewrite the call — not
  something this project should rely on; rewriting the operation the policy
  just evaluated is its own bypass surface). Silent/empty stdout with exit 0
  is also treated as allow.
- **`deny`**:
  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": "string"
    }
  }
  ```
  A legacy shorthand also works: `{"decision": "block", "reason": "..."}`.
  Exit code 2 with the reason on stderr is an equivalent alternative to the
  JSON form.
- **`ask` IS a supported `permissionDecision` value in codex-cli 0.146.0.**
  This corrects an earlier reading of the documentation, and the correction is
  first-hand — see "Verified against the installed binary" below. The wire enum
  is `["allow", "deny", "ask"]`.

  > **Superseded claim, kept deliberately.** This document previously stated
  > that `ask` was "not yet supported; treated as a configuration error", and
  > concluded that `OperationIntent`'s `ask` decision "has no wire
  > representation" and must be resolved inside our own process before exiting.
  > That conclusion shaped the CLI: an internal `ask` currently maps to a wire
  > deny. **The premise was wrong for this version.** The behaviour is still
  > *safe* — denying is strictly more restrictive than asking — but it is more
  > restrictive than it needs to be, and the reason recorded for it no longer
  > holds. Whether to emit `ask` is a design decision, not a protocol
  > constraint, and it should now be taken on its merits.

  **Decided on 2026-08-07: the `ask` → wire-deny mapping stays**, now as a
  choice rather than as a misreading. Deny is strictly more restrictive than
  ask, so the mapping cannot admit anything asking would have blocked. `git
  status` settles at `ask`, which makes this the common path rather than an
  edge case, so switching it would change what an operator sees on nearly every
  interpreted command — and there is no live host integration yet to test that
  change against. Revisit when there is: the reason to keep it is the absence of
  a way to verify the alternative, not a belief that asking is wrong.

  It is left recorded rather than deleted because a claim that shaped an
  implementation should not vanish when it turns out to be wrong; the next
  reader needs to know why the code does what it does.

### Verified against the installed binary

Read-only inspection of `codex.exe` from `@openai/codex` (codex-cli 0.146.0),
performed 2026-08-07 with the operator's explicit authorisation, because this
repository otherwise stays inside its own boundary. The binary embeds the JSON
Schema for its own hook wire, which is a primary source rather than prose about
one. Method: extract printable strings from the binary and read the embedded
schema definitions. No Codex process was run and nothing was written.

```json
"PreToolUsePermissionDecisionWire": {
  "enum": ["allow", "deny", "ask"],
  "type": "string"
},
"PreToolUseHookSpecificOutputWire": {
  "additionalProperties": false,
  "required": ["hookEventName"],
  "properties": {
    "hookEventName":            { "const": "PreToolUse", "type": "string" },
    "permissionDecision":       { "$ref": "…PreToolUsePermissionDecisionWire" },
    "permissionDecisionReason": { "type": "string" },
    "additionalContext":        { "type": "string" },
    "updatedInput":             {}
  }
}
```

Three facts follow, each now first-hand rather than inferred:

1. **The allow object this project emits is correct.**
   `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
   matches the schema: `hookEventName` is the only required member, and `allow`
   is a valid decision. This closes an open item — the shape had been inferred
   from the documented deny form and flagged in the code as unconfirmed.
2. **`ask` is a valid wire decision**, as above.
3. **A wire `deny` object requires a non-empty `permissionDecisionReason`.** The
   binary carries the rejection message `PreToolUse hook returned
   permissionDecision:deny without a non-empty permissionDecisionReason`. This
   project's deny path uses exit code 2 rather than the JSON object, so it is
   unaffected — but anything that later switches to the object form must carry a
   reason, and a hook rejected for this would fail, and failure is open.

The binary also rejects `continue:false`, `stopReason` and `suppressOutput` on
`PreToolUse`, and `reason` without `decision`.

**Scope of this evidence.** It is one version on one platform: codex-cli
0.146.0, `x86_64-pc-windows-msvc`. The wire is not versioned in a way this
project can assert against at runtime, so this is evidence about the host that
was installed on one machine on one day, not a standing guarantee. The adapter's
`INPUT_PROTOCOL_REVISION` remains the thing to bump when re-verified.

### Failure handling — the host fails open, not closed

This is the finding most worth designing around:

| Condition | Codex's behavior |
|---|---|
| Malformed JSON on stdout | Hook marked failed; **tool call proceeds** |
| Missing/empty stdout, exit 0 | Treated as success/allow |
| Unsupported output fields (`continue`, `stopReason`, `suppressOutput` in a `PreToolUse` response) | Hook marked failed; **tool call proceeds** |
| Timeout (>600s) | Hook failure recorded; behavior on the call itself matches the "hook failed" fail-open pattern above |
| Exit code 1 | Hook run marked failed |
| Exit code 2 | The one explicit-block path — stderr becomes the deny reason |

Every one of these failure modes resolves to the operation proceeding,
**not** to a block. This directly conflicts with this project's own fail-safe
principle (PRD §4.8, §11) — but the conflict is in the host, which is out of
scope to change. The practical implication for Milestone 1/2:

> The hook entrypoint must be structurally incapable of crashing, hanging
> past a self-imposed sub-timeout (well under 600s), or emitting anything
> Codex can't parse as a valid `deny` — because every one of those failure
> shapes silently degrades to allow at the host level, not ours.

Concretely: wrap the entire process in an outermost handler that is
guaranteed to emit a well-formed exit-2-with-stderr (or valid JSON `deny`)
on any uncaught exception, and enforce our own timeout well inside 600s so
we hit it before Codex's does.

## `PostToolUse` and `Stop` (brief, not load-bearing for Milestone 1)

- `PostToolUse`: runs after the tool already executed. Cannot undo side
  effects — useful only for audit/feedback, not enforcement. Can replace the
  tool result with feedback via exit 2 or `decision: "block"`.
- `Stop`: fires when a turn completes. `decision: "block"` triggers an
  automatic continuation prompt — it does not reject the turn outright.

## Open items this research does NOT resolve

- The exact relative path/name Codex expects for this plugin's `hooks.json`
  once `hooks/` has real content (docs show the manifest key as
  configurable; needs confirming against this plugin's actual layout).
- Whether a hook's own **crash** (not just malformed output) is
  distinguishable from a hook that legitimately exits 1 — both may collapse
  to the same "hook failed → proceed" host behavior; worth a live probe
  before Milestone 2's real hook integration.

These are good candidates for a short live-fixture spike early in
Milestone 1, using Codex's own diagnostic-command pattern (FR-005) against a
disposable sandbox session rather than further doc-reading.
