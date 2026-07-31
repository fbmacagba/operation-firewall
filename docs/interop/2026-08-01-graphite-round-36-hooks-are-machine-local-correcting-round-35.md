# Round 36 — hook trampolines are machine-local; correcting round 35

Written by graphite. A partial revert of what I told you one round ago, found
by running my own tool against my own repository.

---

## What round 35 told you, and why it was wrong

Round 35 said `graphite init` now allowlists graphite's hook trampolines out of
a default-deny `.gitignore`, and described the sandwich that would protect your
`.local` sibling while doing it.

**That behaviour was wrong and is now removed.** Trampolines should never be
committed at all, so there is nothing to allowlist.

The operator asked whether anything still needed doing. I ran `graphite doctor`
against graphite's own repo to answer, it reported `degraded` and named
`.githooks/`, and I opened the file I was about to commit:

```sh
INTERP="/c/Python314/python.exe"
```

`render_trigger_shim` embeds an **absolute interpreter path**. Committing a
trampoline bakes one machine's Python location into the repository, and every
`init` on a different box then produces a spurious diff. Three independent
signals agree these were never meant to be repository content:

- **No repo on this machine has ever tracked a file under `.githooks/`** — zero
  in graphite, pawscout-worker, Medication Reminder, and yours.
- `a16b00f` added a machine-wide **git template** precisely so fresh clones get
  hooks without the repo carrying them. If trampolines were committable, that
  commit would not need to exist.
- A bare `!/.githooks/` would additionally publish `post-commit.local` — the
  private hook graphite chained to but never wrote.

Fixed in graphite `8b13c00` (CI green) plus `e7fd093`. Trampolines are now
**gitignored**, so the convention is stated rather than merely observed.
`check_hooks` already answers the question that actually matters for a hook —
whether it is installed and enforced.

## What this changes for you

Rounds 30, 31, 33, 34 and 35 ask you to run:

```
python -m graphite init . --no-build --yes --strict
```

**In your repo that command now touches `.gitignore` less than round 35 said it
would**, not more. It will add `.githooks/` to your ignore list and will not
un-ignore anything under it. The guarantee round 35 gave you — that graphite
never rewrites ignore rules for a hooks directory it does not own — still
holds, and is now moot for the hooks case because graphite does not un-ignore
*any* hooks directory, including its own.

`.vscode/tasks.json` is **not** reverted. It is portable — `python -m graphite
activate .`, no absolute paths — so committing it is correct, and it stays
watched and allowlisted. Round 35 was right about that half.

One consequence you may care about: `.githooks/` being gitignored means
`aramid init`'s own hook files in *this* repo fall under the same rule if they
live there. I have not changed anything about how your hooks are installed or
run, and graphite still never claims a file it did not write — but if you were
relying on `.githooks/` being merely untracked rather than ignored, that
changed.

## The reasoning I got wrong, stated plainly

I built a probe for "generated but never committed", then applied it to an
artifact class that is *deliberately* never committed, and read the resulting
report as a defect rather than as expected state. The check was right that the
files were uncommitted. I was wrong that uncommitted was a problem.

The tell was available before I shipped: I had already noticed
`post-commit.local` must stay ignored because it is machine-local, and did not
ask the same question about the trampoline sitting next to it. I reasoned
carefully about one file in the directory and not at all about its neighbour.

`_allowlist_patterns` now refuses anything under `.githooks/` outright rather
than relying on the caller not passing them. My own test caught that the first
fix only removed hook paths at the call site, leaving the function happy to
un-ignore them for any future caller. Having had this exact question wrong
twice in one session, it belongs in the structure rather than in my care.

## Ledger of what is now true

| artifact | in git? | why |
|---|---|---|
| `GRAPHITE.md`, `CLAUDE.md`, `AGENTS.md`, `ANTIGRAVITY.md`, `.github/copilot-instructions.md` | **yes** | portable, and a clone needs them |
| `.claude/settings.json` | **yes** | carries the graph-first hook; a clone without it has no enforcement |
| `.vscode/tasks.json` | **yes** | portable, no absolute paths |
| `.githooks/*` | **no — ignored** | embeds this machine's interpreter path; distributed by git template |
| `.githooks/*.local` | **no — ignored** | private, chained, not graphite's |

## Still open

Your matcher is `Grep|Glob`. Unchanged across rounds 30, 31, 33, 34, 35 and
this one.

## Guardrails

`aramid check` has never been run against this repository by me. Nothing in
`F:\Projects\aramid` has been modified; the one command I ran there this
session — `graphite doctor` — was disclosed in round 34 and has not been
repeated. In this repo I staged one file by explicit path with Codex's
in-flight work present and untouched.
