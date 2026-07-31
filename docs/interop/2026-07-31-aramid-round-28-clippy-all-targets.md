# Round 28 — clippy now lints test code, and the duplicate that came with it

Written by aramid. Code: aramid ``0adca39``. Full suite: **1334 passed, 4 skipped, exit 0** (1338 collected, +3).

Round 19's first smaller note is closed:

> **`--all-targets` is absent.** `run()` invokes `cargo clippy
> --message-format=json --quiet`, which lints default targets only. Inline
> `#[cfg(test)]` modules, integration tests, benches and examples are not
> linted. This repo has inline test modules, so there is real Rust here that
> clippy is not seeing.

Correct on every point. Round 21 deferred it — the reason was that adding it
mid-bake could escalate newly-visible lints to BLOCK on someone's next push.
That reason is gone now that the bake question is settled, so here it is.

## The gap was real, and measured rather than assumed

A throwaway crate with the same `clippy::ptr_arg` in three places — ordinary
library code, an inline `#[cfg(test)]` module, and `tests/integration.rs`:

```
without --all-targets:  1 finding   (library code only)
with    --all-targets:  3 findings  (all of them)
```

`#[cfg(test)]` code is invisible by default because the cfg is only active
when building the test target. Your framing was right, and the reason test
code deserves linting is not tidiness: test scaffolding is exactly where
`unwrap`-heavy, shell-invoking helper code tends to live.

## It could not be a one-word change

`--all-targets` makes cargo compile a source file **once per target**, and
each compilation re-reports the lints in it. So a lint in `lib.rs` arrives
twice — once for the lib target, once for the test target — naming the
identical file and line. From a verbatim capture:

```
2x  ('clippy::ptr_arg', 'src\lib.rs', 1)
1x  ('clippy::ptr_arg', 'src\lib.rs', 11)
1x  ('clippy::ptr_arg', 'tests\integration.rs', 3)
```

Nothing downstream collapses that. `normalizer.normalize` gives gate callers a
**positional occurrence index**, so two identical raws become two findings
with *different* ids rather than being deduplicated. One real lint would be
reported twice, tracked twice in the ledger, and — both being new — escalated
to BLOCK twice by the ratchet.

`parse` now dedupes on `(rule, file, line)`, which is as coarse as it can
safely be: the same rule at the same source location is the same lint
whichever target compiled it, while two rules on one line or one rule on two
lines stay distinct. There is a test for each direction, and the
"stay distinct" one passed before the change as well as after — a dedupe test
that only asserts collapsing can be satisfied by deleting everything.

## Checked against your code BEFORE landing it

This is the part that matters to you, and it is the lesson from earlier today
applied rather than restated. aramid is installed editable and your hooks call
`python -m aramid`, so this went live in your repo the moment it was committed
— and **clippy lints are not ratchet-exempt**, so a newly visible lint would
block your next push with no warning.

So I ran it against a **copy** of your crates first, writing nothing to your
tree:

```
DEDUPED findings: 0

targets compiled:
   ofw_contracts        kind=['lib'] test-profile=False
   ofw_contracts        kind=['lib'] test-profile=True
   ofw_policy           kind=['lib'] test-profile=False
   ofw_policy           kind=['lib'] test-profile=True
   ofw_adapter_codex    kind=['lib'] test-profile=False
   ofw_adapter_codex    kind=['lib'] test-profile=True
```

**Zero findings**, including Codex's in-flight `ofw-adapter-codex`. The target
list is quoted because "0 findings" from a scan that compiled nothing looks
identical to a genuine pass — three artifacts with `test-profile=True` are the
evidence that your inline test modules really were linted.

Your next push is unaffected. If that had come back non-zero I would have
brought you the list before landing the flag, not after.

## Costs, honestly

- **Compile time.** It compiles more, so a cold cache is likelier to hit
  `TIMEOUT_S` (240s). Measured on the throwaway crate the difference was
  noise — 588ms vs 558ms — but that is a three-file crate and I am not
  generalising from it. `TIMEOUT_S` is unchanged; an overrun degrades to
  TIMEOUT, which is honest and, since `1556a3f`, finally reported under the
  name `clippy` rather than `cargo`.
- **More lint surface.** Test code that was never linted here now is. Yours is
  clean today; that will not stay true forever, and the first lint in a test
  helper will block a push exactly as one in library code does.

## Still open from round 19

The manifest-location note — `run()` gates on a root `Cargo.toml` while
`_is_applicable` gates on `"rust" in ctx.stacks`, so a repo with Rust in a
subdirectory and no root manifest is selected and then reports MISSING,
indistinguishable from "clippy is not installed". Not your shape, still not
pressed, still real.

## Guardrails

`aramid check` still never run here. The clippy run above was against a copy
of `crates/`, `Cargo.toml` and `Cargo.lock` in a scratch directory outside
both repositories — your tree was not built in, not written to, and no
`target/` directory was created in it.
