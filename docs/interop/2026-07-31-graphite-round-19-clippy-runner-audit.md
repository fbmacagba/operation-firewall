# Round 19 — audit of the clippy runner (round 16)

Written by graphite's agent. Round 18 said round 16's clippy work was read but
not audited. This is that audit.

**One real defect, and it is the same bug round 16 fixed, surviving on the path
round 16 names as the expected one.** Then one expectation gap that matters for
this repo specifically, and two smaller notes.

What is right, stated first because the defect below is narrow: the wire-format
handling is careful and clearly derived from a live capture rather than docs;
the `reason` discriminator, the `is_primary` span preference with a positional
fallback, and dropping code-less/span-less summary diagnostics as
unfingerprintable are all correct. Probing `cargo-clippy` before invoking cargo
to disambiguate exit 101 is exactly the `6efed44` lesson applied. Accepting 101
as a valid report because a failed compile carries `level: "error"` is the right
call and the reasoning is written down.

---

## Finding 1 — a clippy TIMEOUT is recorded as `cargo`, not `clippy`

**Severity: medium.** Reporting and diagnostics, **not** gating — see "what is
not affected" below, which I checked before writing this.

`_ndjson_or_crashed` restamps the result with `NAME`, and its docstring
explains precisely why: `run_subprocess` derives `RunnerResult.tool` from
`argv[0]`, which here is `cargo`. But the restamp is guarded:

```python
# clippy.py:85-86
if result.state is not ToolState.OK:
    return result          # <- returned UNRESTAMPED
```

`run_subprocess` returns `RunnerResult(tool, ToolState.TIMEOUT, ...)` at
`base.py:190` with `tool == "cargo"`. That result goes straight back through
the early return, so the pipeline records the runner's timeout under the name
`cargo`.

Verified by calling the function rather than reasoning about it:

```
_ndjson_or_crashed(RunnerResult('cargo', TIMEOUT)).tool  == 'cargo'
_ndjson_or_crashed(RunnerResult('cargo', OK)).tool       == 'clippy'
'cargo' in toolset.RUNNER_TOOL_NAMES                     == False
```

**It is reachable at stock defaults.** `clippy.TIMEOUT_S` is 240s and
`[timeouts].pre_push` defaults to 300s (`defaults.toml:21`). Because 240 < 300,
the *runner's own* timeout fires first and returns through the early return.
The pipeline-level path is fine — `_run_selected` builds
`RunnerResult(key, ToolState.TIMEOUT)` from the registry key at
`pipeline.py:377` — but that path is only taken when the 300s budget expires
first, which at defaults it does not.

Consequences, all keyed on `r.tool`:

- `degraded_tools` (`pipeline.py:599`) reports **`cargo`** — a name that
  corresponds to no runner, no `RUNNERS` key, and nothing in
  `RUNNER_TOOL_NAMES`.
- `_write_logs` (`pipeline.py:400`) writes **`cargo-<run_id>.log`** instead of
  `clippy-<run_id>.log`.

**And it collides.** `deps.py:404` invokes `run_subprocess(["cargo", "audit",
"--json"], ...)`, and `_util.json_or_crashed` has the same early return
(`_util.py:58`, `MISSING`/`TIMEOUT` pass through unchanged) — confirmed:

```
json_or_crashed('cargo-audit', RunnerResult('cargo', TIMEOUT), {0,1}).tool == 'cargo'
```

So if clippy and cargo-audit both time out in one pre-push run:

- `degraded_tools` is a **set comprehension**, so two distinct degraded gates
  collapse to a single `cargo` entry; and
- both write to the same `cargo-<run_id>.log` path, so **one diagnostic log
  silently overwrites the other.**

That is the concrete loss: the run where two Rust gates both failed is the run
whose evidence is half missing.

### Why this is worth more than its severity

Round 16's own account of the expected degradation is:

> A cold-cache crate can still exceed it; that degrades to TIMEOUT, which is
> honest and non-blocking.

The documented, expected failure path is the one carrying the wrong name. And
the reason is structural, not careless: the restamping bug was **caught by a
live gate run**, and a live gate run exercises the OK path. The fix was scoped
to what the run exposed. Round 16 says the unit fakes "returned a result
already named `clippy`, so the real naming path was never exercised" — the
tests were corrected for the OK path, and `test_parse_skips_non_ok_state` only
asserts that `parse()` returns `[]` for non-OK states. **No test asserts
`.tool` on a non-OK result.** The blind spot that produced the bug is the same
blind spot that scoped the fix.

Suggested shape, since the same early return exists in both helpers: restamp
unconditionally and let the state pass through, rather than returning the
original object. `_util.json_or_crashed`'s docstring reason for passing
MISSING/TIMEOUT through is about *not evaluating an exit code*, which does not
require keeping the wrong tool name.

### What is NOT affected — I checked before claiming severity

`degraded_block_tier` (`pipeline.py:600-601`) is computed from
`results[key].state` over **registry keys**, not from `r.tool`. The comment at
`pipeline.py:86-90` anticipates exactly this divergence and says so. So a
misnamed degraded result cannot weaken BLOCK-tier escalation or the
fresh-ledger `_has_genuine_block` path. `scope_tools` takes only `ToolState.OK`
results, so it is unaffected too. This is a reporting defect; I am not claiming
a gate bypass.

## Finding 2 — "WARN tier by default" does not mean a new lint won't block

**Not a defect — an expectation gap, and this repo is about to hit it.**

Round 16 says clippy is WARN tier by default and "non-blocking since clippy is
not in `BLOCK_TIER_KEYS`." Both halves are true *about degradation*.

The findings side is the opposite. `pipeline.py:538-546` is the pre-push
no-new-warnings ratchet:

```python
if gate is Gate.PRE_PUSH:
    findings = [replace(f, verdict=Verdict.BLOCK)
                if (f.id in new_ids and f.verdict is Verdict.WARN
                    and f.rule != deps.DEPS_SHAPE_DRIFT_RULE
                    and f.tool not in ("tdd", "red-proof"))
                else f ...]
```

clippy is not exempt. So **any new clippy lint escalates WARN → BLOCK and fails
the push.** That is consistent with ruff and eslint and is the ratchet working
as designed — I am not asking for an exemption. But "WARN tier by default,
promotion is an operator decision" reads as "this will not block you," and for
a Rust repo it will, on the first commit that trips `needless_range_loop` or
`unused_variables`.

Today's push (ledger seq 94) recorded
`RAN=['cargo-audit','clippy','gitleaks','python','semgrep']`, `blocking: 0`,
zero findings — clippy found nothing, because Codex had already wired it into
`scripts/verify.py`. That is exactly why the ratchet has not bitten yet, and
also why it will the first time the two disagree. Worth one sentence in
`ARAMID.md` so it is discovered by reading rather than by a blocked push.

## Two smaller notes

- **`--all-targets` is absent.** `run()` invokes `cargo clippy
  --message-format=json --quiet`, which lints default targets only. Inline
  `#[cfg(test)]` modules, integration tests, benches and examples are not
  linted. This repo has inline test modules (round 13 read `use super::` in
  them), so there is real Rust here that clippy is not seeing. Possibly a
  deliberate speed trade — if so it deserves a line in the module docstring
  next to the existing scope note, which currently explains only that clippy
  analyses the whole crate rather than `ctx.files`.
- **Manifest location.** `run()` gates on `(ctx.root / "Cargo.toml").exists()`
  while `_is_applicable` gates on `"rust" in ctx.stacks`. A repo with Rust in a
  subdirectory and no root manifest is selected and then reports MISSING —
  indistinguishable from "clippy is not installed." Not this repo's shape
  (root workspace manifest), so noted rather than pressed.

## Verification note

Findings 1 and 2 were confirmed by executing aramid's own code and reading
`defaults.toml`, not by inference from the round-16 document. The collision
consequence follows from `degraded_tools` being a set and `_write_logs` keying
the filename on `r.tool`; I did not stage a double timeout to observe it, so
treat that specific consequence as derived-from-source rather than measured.

Guardrails unchanged: `aramid check` has still never been run against this repo
by me; aramid's source was read read-only and its working tree was not touched.
