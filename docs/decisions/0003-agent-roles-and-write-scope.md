# ADR 0003: Agent roles, write scope, and the interop protocol

- Status: Proposed
- Date: 2026-07-31
- Deciders: Operation Firewall maintainers

## Context

Three autonomous agents write to this repository: Codex (implementation), aramid (security review and its own tooling), and graphite (code graph and git-hook management). No document states which of them may write where. The arrangement has been inferred from practice and re-negotiated in correspondence.

Round 6 (`docs/interop/2026-07-30-aramid-round-6-role-scope-proposal.md`) proposed a role split. It was never ratified, and by round 20 it had gone stale in three verifiable ways:

- Its central mechanism was that graphite distills aramid's review into `docs/reviews/` for Codex. `docs/reviews/` has not been written since `d4e7281` (2026-07-30) — before round 10. Eleven rounds have happened since, all written directly to `docs/interop/`.
- It states that aramid "stays read-only everywhere outside `docs/interop/`". That is false: `aramid init` regenerates `ARAMID.md` and writes hooks and repo config by design, as round 12 records.
- It models aramid as reviewer and graphite as distiller. Practice is now bidirectional — graphite files change requests (round 14), aramid ships code (rounds 15–17), graphite audits that code and files defects (round 19).

The failure is structural, not editorial. A standing rule filed as correspondence is read once, on the day it is written. Nobody re-reads round 6 at round 20, so the rules drifted silently from the text that was supposed to govern them. Standing rules need a home that is current and indexed, which is what this ADR series is for — rounds 13 and 19 already audit code against ADR 0002's clauses, so ADRs are load-bearing here rather than decorative.

This document is already being followed while still Proposed, which is evidence for it rather than against: round 21 filed its correction to round 17 as a new round rather than editing round 17 in place, citing this ADR and calling its reasoning better than the practice rounds 10 and 11 used; and the round-25/26 filename collision was resolved by the later author renaming, per the protocol below. That is three agents converging on rules nobody has ratified.

A second, independent problem: **every commit in this repository is authored `jared0565 <jared0565@gmail.com>`.** All three agents are indistinguishable in git history. Any write-scope rule is therefore unenforced and unauditable — the only signal of authorship is a filename convention held by good faith.

## Decision

Ratify the roles as actually practised, not as round 6 described them. Round 6 is superseded by this ADR and should not be cited as governing.

**Codex owns implementation.** The PRD, threat model, architecture, this ADR series, and all source under `crates/`, `scripts/`, `policy/`, and `provenance/`. All design and implementation decisions are Codex's, including whether to act on any finding raised by the other two agents. Milestone documentation under `docs/milestone-*/` is Codex's.

**aramid owns security review and its own tooling.** In this repository it writes only: its own round documents in `docs/interop/`, and the files its own `init` generates — `ARAMID.md`, `.githooks/`, and `aramid.toml`. It does not write source, ADRs, or the PRD. **`aramid check` is never run against this repository**; its ledger and cache are the repository's, and populating them from a review session corrupts the record that the real gate depends on. Review is performed against aramid's own fixtures, and findings are reported here.

**graphite owns the code graph and hook management.** `graph-out/`, `GRAPHITE.md`, the graphite-managed agent instruction files, and its git-hook trampolines. It writes its own round documents in `docs/interop/`. It audits claims made by the other agents and reports findings, and it may make judgment calls on matters delegated to it in writing. **It does not design or implement the enforcement engine.** A request that it write engine code is a scope change and must be confirmed with the maintainer before proceeding.

**`docs/interop/` is the shared channel and follows one protocol.**

- One file per round, named `YYYY-MM-DD-<agent>-round-<N>-<topic>.md`.
- `N` is monotonic across all agents, not per-agent.
- **Re-read the directory for the highest `N` in the same action that names the file**, not at the start of drafting. Both collisions on 2026-07-31 happened in the gap between choosing a number and committing it.
- A collision discovered before commit is resolved by renaming, which is free. A collision discovered after commit is resolved by the later author renaming their own file, never the earlier one.
- **No agent edits another agent's round document.** Disagreement, correction, and response all go in a new round.
- An agent correcting its own committed round does so in a new round as well, so the record shows the correction rather than hiding it.

**Concurrency.** Any agent must run `git status` immediately before staging, and stage only its own files by explicit path. Never `git add -A`. The working tree routinely carries another agent's in-flight work.

**No agent grants itself scope.** Changes to this ADR are the maintainer's decision. Two agents agreeing between themselves does not ratify anything.

## Open sub-decision — commit attribution

This ADR cannot move to Accepted until this is resolved, because the rules above are otherwise unenforceable and unauditable.

1. **Accept single-identity commits.** Cheapest; no tooling change. Authorship remains inferable only from paths and filenames. Adequate if the agents are trusted and the audit trail is not a security control.
2. **Per-agent `Co-Authored-By` trailers.** Each agent appends a distinct trailer. Cheap, greppable, preserves a single committer identity. Does not survive a squash.
3. **Per-agent git identities.** Each agent commits with its own `user.name`/`user.email`. Strongest attribution and `git log --author` works. Requires per-agent git config and makes the agents visible in any published history.

Recommendation: option 2, escalating to 3 if the audit trail ever becomes a compliance artifact rather than an operational convenience.

## Consequences

New agents, and new sessions of existing agents, read one current document instead of reconstructing rules from twenty rounds of correspondence. The interop protocol becomes checkable — a round file either follows the naming rule or does not.

The cost is that this document goes stale exactly as round 6 did unless it is superseded when practice changes. The mitigation is the `Status` field: when the arrangement changes, write ADR 0004 and mark this Superseded, rather than editing it in place.

This ADR governs process only. It grants no agent any authority over the enforcement engine's design, and it does not alter any security control.

## Rejected alternatives

**Ratify round 6 as written.** Rejected: three of its clauses are contradicted by observed practice, so ratifying it would ratify things no agent does.

**Leave the arrangement in correspondence.** Rejected: this is the failure mode being fixed. Round 6 sat unratified through fourteen rounds precisely because correspondence is append-only and not re-read.

**Let the agents ratify it between themselves.** Rejected: a standing multi-agent write-access arrangement on a maintainer's repository is the maintainer's decision. Both aramid and graphite independently declined to accept it on their own authority, which was correct.

**Per-agent directories with no shared channel.** Rejected: the value of `docs/interop/` is that disagreement is visible in one ordered thread. Round 15's correction of round 11, and round 19's audit of round 16, are only legible because they sit in sequence.

## Rollback and compatibility

Supersede with a new ADR and set this one to `Status: Superseded by ADR NNNN`. Do not edit the decision in place; the history of changed arrangements is itself useful.

Round 6 is superseded on acceptance of this ADR. Rounds 1–20 remain valid as correspondence and as the evidentiary record; nothing in them is retracted by this document.
