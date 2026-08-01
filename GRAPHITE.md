<!-- graphite:managed version=11 -->
# Graphite Development Context

Graphite is the shared local code graph for this project. Codex, Claude Code, Gemini CLI, Antigravity, Visual Studio, and other coding agents should use the same graph instead of rebuilding separate mental maps.

All commands below use `python -m graphite`, which works in every shell and for every agent as long as the Python environment has Graphite installed. A bare `graphite` command is equivalent where the console script is on PATH.

## Required Workflow

Graphite-first is required, not advisory. Before any cross-file exploration, consult the graph first. Manual search (grep, glob, directory walking) is the fallback, not the default: use it for literal text and filename lookups, or after a Graphite answer proved insufficient — and say so when you fall back.

| Question shape | Run first |
| --- | --- |
| Who calls / reads / imports this symbol? | `python -m graphite query "callers <symbol>"` |
| What does this symbol call? | `python -m graphite query "calls <symbol>"` |
| Where is this symbol defined? | `python -m graphite search "<symbol>"` |
| What breaks if this file changes? | `python -m graphite impact <file>` |
| What surrounds this file (callers, tests, neighbors)? | `python -m graphite context <file>` |
| How is the project structured? | `python -m graphite query "stats"` |
| Literal string or filename lookup | grep/glob — Graphite not required |

Before non-trivial code changes:

1. Run `python -m graphite check .`
2. Run `python -m graphite context <target-file>` before editing important files.
3. Run `python -m graphite impact <target-file>` before changing shared logic, APIs, data flow, auth, persistence, deployment behavior, or other high-risk paths.
4. Use `python -m graphite search "<symbol, path, or concept>"` to locate nodes; use `python -m graphite query "stats"` when project structure is unclear.
5. Discover supported commands, query verbs, and limits with `python -m graphite capabilities --json` — do not guess query verbs. `query` takes structured verbs; `query --natural "<question>"` accepts only the fixed deterministic grammar listed by capabilities (no inference — unmatched questions fall back to ranked search).
6. Graph answers carry an `answer` block: `grade: decision_grade` means this answer's own relations/languages are healthy (an empty result is a trustworthy absence, subject to `caveats`); `advisory` means verify with grep and say so; `inconclusive` (also the legacy `"inconclusive": true`) means unknown, not safe. Check `known limits`/`caveats` before trusting empties.
7. `python -m graphite incidents list` shows recorded failures (build errors, malformed artifacts, inconclusive queries). Check it when a graph answer looks wrong; recurring incidents belong in a governed round.

After edits:

1. Run `python -m graphite build .` when `python -m graphite check .` reports the graph stale. Otherwise this repo's graph refreshes on its own while it is open in a coding agent.
2. Run relevant tests, typechecks, or validation commands.
3. Do not edit `graph-out/` manually.

Graph freshness is never a reason to avoid the graph. Always query it for
relationship questions: every answer carries its own `answer.grade`, so trust
that rather than guessing whether the graph is current. If an answer comes back
`inconclusive` or insufficient, fall back to search and say that you did.

## Repository Isolation

**Your repository is your world.** Do not read, write, or run commands in any other repository — including its `graph-out/`. This holds even when the other repo sits on the same machine, is a dependency of this one, or plainly contains the answer you need.

Cross-repo knowledge travels one way only: as a **recommendation**, through the shared interop channel, addressed to the agent that owns that repository. That agent decides and acts. A defect you find elsewhere is a request, never a patch — and never a read.

- Do not open another repo's source, tests, config, or `graph.json`. Each repo's graph describes that repo and belongs to its agent.
- Do not run any command with another repository as its working directory or root, including read-only ones such as `status`, `doctor`, or a test suite.
- Do report what you observed from your own side, and ask the owning agent to look. Say plainly which parts you could not verify.
- Do act on what another agent tells you about their repository, and attribute it to them.

**If you need a fact from another repo, ask for it.** A claim clearly labelled unverified is safer than a verified one obtained out of bounds — the boundary is the control, and stepping over it to be thorough defeats it.

Graphite invoked as a *tool* against an onboarded repository (`graphite init`, template rollout) is the operator's tooling rather than an agent crossing a boundary. That exemption belongs to the operator running the command, not to you.

## Canonical Graph Isolation

`scan`, `build`, `report`, `check`, `validate`, `query`, `context`, `impact`,
`watch`, and `daemon` are inference-free canonical operations. They do not read
provider credentials, ignore ambient `GRAPHITE_LLM*` configuration, and reject
legacy non-`none` LLM flags. Model-generated annotations belong only in the
explicit, non-authoritative overlay boundary and must never replace or modify
canonical `graph-out` artifacts.

## Operating Rules

- Treat Graphite as a project map, not as proof of correctness.
- Always read the source files and tests that Graphite identifies before changing behavior.
- Graphite-first: prefer graph commands over manual cross-file search; fall back only when the graph answer is insufficient, and say so.
- If `python -m graphite check .` reports stale output, rebuild before relying on context or impact data.
- Canonical Graphite operations run locally and never use LLM or network inference.
- For TypeScript resolver issues, use `python -m graphite --typescript-resolver disabled build .` only as a fallback.
- Stay inside this repository: no reads, writes, or commands in any other repo or its graph. Findings about another repo go to its agent as a recommendation.
<!-- graphite:managed-end -->
