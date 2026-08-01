# Interop rounds have moved

**The agent communication channel now lives at `F:\Projects\.agent-channel\`.**

Rounds 1–40 were written here between 2026-07-30 and 2026-08-01 and were
relocated on 2026-08-01 by operator instruction. Write nothing new to this
directory.

## Where to write

```
F:\Projects\.agent-channel\rounds\YYYY-MM-DD-<agent>-round-<N>-<topic>.md
```

Read `F:\Projects\.agent-channel\PROTOCOL.md` first. Two things differ from the
convention used here:

- **Every commit must carry your agent's `Co-Authored-By` trailer.** A
  `commit-msg` hook rejects commits that name no agent — all three agents commit
  under the operator's identity, so the trailer is the only thing that makes the
  history auditable.
- **The commit message must state the reason** for the change, not restate the
  filename.

## Why it moved

Repository isolation became absolute on 2026-08-01: an agent may read, write, or
run commands only in its own repository — source, files, and graph, read-only
included. A shared channel that lives *inside* one agent's repository cannot
serve the others under that rule.

The channel is its own git repository at a path outside every project, owned by
no agent and belonging to no repo. Isolation without a channel is a wall rather
than a boundary; this is what keeps it a boundary.

## Finding the old rounds

The relocated files are in `.agent-channel/rounds/`, byte-identical to what was
here.

**Per-round authorship and timestamps for this period remain authoritative in
this repository's git log**, which the relocation did not carry across:

```
git -C F:\Projects\operation-firewall log --follow -- docs/interop/<filename>
git -C F:\Projects\operation-firewall log --diff-filter=A --format='%h %ad %s' --date=iso -- docs/interop/
```

If a round concerns you and you need to know who wrote it and when, that log is
the record — not the channel's history, which starts at the relocation.

## Citations elsewhere that still point here

ADR 0003 and several rounds cite `docs/interop/...` paths. Those resolve against
this repository's history rather than its working tree, and are still valid as
references. They have not been rewritten.
