# Research: Codex `PreToolUse`/`PostToolUse`/`Stop` hook protocol

Status: informational research, not a design decision. Feeds PRD.md §20 open
decision #2 ("Exact Codex hook protocols and execution paths available to the
first integration").

Sources: official docs at `developers.openai.com/codex/hooks` (redirects to
`learn.chatgpt.com/docs/hooks`), corroborated against local examples of
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

For `Bash`/`apply_patch`, `tool_input` carries a `command` field. For MCP
tools, `tool_input` is the tool's own argument object.

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
- **`ask` is not a supported `permissionDecision` value.** Docs describe it
  as "not yet supported; treated as a configuration error" if emitted.
  **Consequence for `OperationIntent`'s `ask` decision (PRD §8.2): it has no
  wire representation.** An `ask` outcome has to be fully resolved inside our
  own hook process — block synchronously on the approval channel (up to the
  600s budget) — before the process exits, then emit only `allow` or `deny`.
  Codex never observes a three-way decision.

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
- Whether `apply_patch`'s `tool_input.command`-equivalent field name matches
  `Bash`'s, or has its own shape — docs excerpt didn't show it in full.
- Whether a hook's own **crash** (not just malformed output) is
  distinguishable from a hook that legitimately exits 1 — both may collapse
  to the same "hook failed → proceed" host behavior; worth a live probe
  before Milestone 2's real hook integration.

These are good candidates for a short live-fixture spike early in
Milestone 1, using Codex's own diagnostic-command pattern (FR-005) against a
disposable sandbox session rather than further doc-reading.
