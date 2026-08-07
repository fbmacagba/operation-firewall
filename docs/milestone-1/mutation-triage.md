# Mutation triage — the 46 survivors

Triaged 2026-08-08 against the `cargo-mutants` report from CI run
[31200208277](https://github.com/jared0565/operation-firewall/actions/runs/31200208277)
at `6db09a0`: **220 mutants, 136 caught, 38 unviable, 46 missed.**

The mutation job was added as advisory precisely so this list could be read
once rather than triaged under pressure to make a build green. This is that
reading. It exists because completion criterion 4 names mutation testing, and a
job whose survivors have never been looked at is evidence of nothing.

## The rule this triage is decided by

The tempting disposition for most of these is "the mutation makes the system
*more* restrictive, so it cannot cause a bypass, so it is acceptable". This
repository has already rejected that argument in its own source. From
`crates/ofw-policy/src/bundle.rs`, on why an empty selector array is refused
even though accepting it would broaden a rule:

> That direction is *more* restrictive and therefore safe, which is exactly why
> it must still be rejected: silently changing what a rule means is a defect
> even when the change is safe.

So the direction of a mutation's effect is recorded below because it sets
severity, **not** because a safe direction excuses a survivor. A survivor means
no test constrains that line. The disposition for all 46 is *kill*.

## How each kill was verified

A test that fails to kill its mutant is indistinguishable from one that kills it
when you only run the suite: the suite passes either way, which is what "missed"
already means. So a passing test is not the evidence here.

Each mutation was applied to the working tree from its own diff in the CI
artifact, its package's tests were run, and the mutant was recorded as killed
only if that run **failed**. The tree is restored and checked clean between
mutants. The script is not committed — it reads an artifact that lives in CI,
not in the repository — but the procedure is:

```
git apply <the mutant's diff>  →  cargo test -p <package>  →  expect failure
git apply -R <the mutant's diff>  →  git diff --stat must be empty
```

`cargo-mutants` is not installed on the authoring machine, by operator decision.
The diffs make that unnecessary for verification; only regenerating the list
needs the tool, and CI does that.

## Effect key

| Term | Meaning |
| --- | --- |
| **wider** | The mutant accepts input the real code refuses. A bound stops bounding. |
| **tighter** | The mutant refuses input the real code accepts. Cannot turn a deny into an allow. |
| **broader rule** | A restriction rule applies to operations it was not scoped to. More denies, wrong scope. |
| **inverted** | Applies where it should not *and* stops applying where it should. Can lose a restriction. |
| **diagnostic** | No decision changes. Operator-visible text or audit provenance only. |
| **panic** | The mutant reaches an unchecked index. In this hook a panic is exit 101, which Codex treats as fail-**open**. |

## Families

### A — Bound checks never tested at their boundary (23 mutants)

By far the largest family, and the reason it is largest is structural: a test
that feeds `MAX + 1` and asserts an error is satisfied by any mutation that
still errors at `MAX + 1`. Only a pair of tests pins a bound — one at exactly
`MAX` asserting acceptance, one past it asserting refusal.

The two mutations differ in severity and it is worth keeping them apart:

- `>` → `>=` refuses exactly `MAX`. **Tighter.** A legitimate input of exactly
  the documented size is refused.
- `>` → `==` refuses *only* `MAX + 1`. **Wider**, and this is the dangerous one:
  every input of `MAX + 2` or more passes a check that exists to bound it. Two
  tests are needed to catch it, at `MAX + 1` and `MAX + 2`, because a single
  over-limit test lands on the one value the mutant still rejects.

One exception to that reading: where the check sits inside a loop after an
incremental insert (`EffectivePolicy::compose`, `tokenize`'s token counter), the
length passes through every value, so `==` and `>=` both fire *earlier* and are
tighter rather than wider.

| Mutant | Effect | Disposition |
| --- | --- | --- |
| `ofw-intent/lib.rs:86` `>`→`>=` (`MAX_COMMAND_BYTES`) | tighter | kill — accept at exactly 65 536 bytes |
| `ofw-intent/lib.rs:153` `>`→`==` (`MAX_TOKENS`) | tighter (in-loop) | kill — see family E |
| `ofw-intent/lib.rs:153` `>`→`>=` (`MAX_TOKENS`) | tighter (in-loop) | kill — see family E |
| `ofw-policy/lib.rs:139` `>`→`==` (prefix length) | **wider** | kill — pin at 4 096 / 4 097 / 4 098 |
| `ofw-policy/lib.rs:139` `>`→`>=` (prefix length) | tighter | kill — same test |
| `ofw-policy/lib.rs:144` `>`→`==` (prefix count) | **wider** | kill — pin at 64 / 65 / 66 |
| `ofw-policy/lib.rs:144` `>`→`>=` (prefix count) | tighter | kill — same test |
| `ofw-policy/lib.rs:213` `>`→`==` (`operation_kinds`) | **wider** | kill — pin at 64 / 65 / 66 |
| `ofw-policy/lib.rs:213` `>`→`>=` (`operation_kinds`) | tighter | kill — same test |
| `ofw-policy/lib.rs:214` `>`→`>=` (`target_kinds`) | tighter | kill — same test |
| `ofw-policy/lib.rs:338` `>`→`==` (`MAX_BUNDLES`) | tighter (in-loop) | kill — accept exactly 32 bundles |
| `ofw-policy/lib.rs:338` `>`→`>=` (`MAX_BUNDLES`) | tighter (in-loop) | kill — same test |
| `ofw-policy/bundle.rs:112` `>`→`>=` (`MAX_BUNDLE_BYTES`) | tighter | kill — accept a bundle of exactly 1 MiB |
| `ofw-policy/bundle.rs:181` `>`→`==` (`safer_alternatives`) | **wider** | kill — pin at 8 / 9 / 10 |
| `ofw-policy/bundle.rs:181` `>`→`>=` (`safer_alternatives`) | tighter | kill — same test |
| `ofw-policy/bundle.rs:216` `>`→`==` (`unique_set`) | **wider** | kill — pin at 64 / 65 / 66 |
| `ofw-policy/bundle.rs:216` `>`→`>=` (`unique_set`) | tighter | kill — same test |
| `ofw-policy/bundle.rs:235` `>`→`>=` (`MAX_ISSUED_AT_LENGTH`) | tighter | kill — accept exactly 35 bytes |
| `ofw-resolve/lib.rs:208` `>`→`==` (`MAX_CONFIGURATION_BYTES`) | **wider** | kill — pin at 65 536 / +1 / +2 |
| `ofw-resolve/lib.rs:208` `>`→`>=` (`MAX_CONFIGURATION_BYTES`) | tighter | kill — same test |
| `ofw-resolve/lib.rs:753` `>`→`>=` (`MAX_PATH_BYTES`) | tighter | kill — accept exactly 4 096 bytes |
| `ofw-resolve/lib.rs:756` `>`→`>=` (`MAX_PATH_SEGMENTS`) | tighter | kill — accept exactly 64 segments |

### B — Three policy selector dimensions were never exercised negatively (9 mutants)

The largest *finding*, as opposed to the largest family. Nine mutants across two
unrelated functions all say the same thing: no test ever asserts that a rule
scoped by `environments`, `reversibility` or `blast_radius` **fails** to match
facts outside its scope. The dimensions are constructed in tests and composed,
but nothing distinguishes them from doing nothing at all.

`operation_kinds` and `operation_effects` are covered — their equivalents at
`lib.rs:164` and `lib.rs:169` were caught. The three that were not are the three
that decide whether a production-scoped deny fires in a local repository.

`matches_set` is the same gap for `target_kinds`: the `||` beside it was caught,
but the function's own return value is unconstrained in both directions.

| Mutant | Effect | Disposition |
| --- | --- | --- |
| `ofw-policy/lib.rs:118` `with_environments` → `Default::default()` | broader rule | kill |
| `ofw-policy/lib.rs:124` `with_reversibility` → `Default::default()` | broader rule | kill |
| `ofw-policy/lib.rs:130` `with_blast_radius` → `Default::default()` | broader rule | kill |
| `ofw-policy/lib.rs:179` `\|\|`→`&&` (`target_kinds` arm) | broader rule | kill |
| `ofw-policy/lib.rs:184` `\|\|`→`&&` (`environments` arm) | broader rule | kill |
| `ofw-policy/lib.rs:189` `\|\|`→`&&` (`reversibility` arm) | broader rule | kill |
| `ofw-policy/lib.rs:519` `matches_set` → `true` | broader rule | kill |
| `ofw-policy/lib.rs:523` delete `!` in `matches_set` | **inverted** | kill — highest severity in this family |
| `ofw-policy/lib.rs:152` `is_empty` → `false` | broader rule | kill — `EmptySelectors` never fires |

The `delete !` mutant is the only one here that can *lose* a restriction: a deny
scoped to `git.worktree_path` would stop applying to `git.worktree_path` and
start applying to everything else. Every other member of this family only ever
adds denies.

### C — `validate_issued_at` is almost entirely unconstrained (5 mutants)

Five of its six branches survive. One of them names a real fragility rather than
a test gap, and it is recorded separately below.

| Mutant | Effect | Disposition |
| --- | --- | --- |
| `bundle.rs:239` `<`→`>` (the `len() < 20` floor) | **panic** | kill — and see "The one real finding" |
| `bundle.rs:250` `\|\|`→`&&` (`-`, `-`, `T` separators) | **wider** | kill |
| `bundle.rs:253` `\|\|`→`&&` (`:`, `:` separators) | **wider** | kill |
| `bundle.rs:258` `!=`→`==` (non-graphic byte scan) | **wider** | kill — accepts control bytes, refuses spaces |

### D — Closed enumerations partially covered (3 mutants)

`environment_from_label` has six arms; three are tested. Deleting an untested arm
sends its label to `_ => None`, so a configuration naming it is refused —
fail-closed, and a silent loss of a documented label.

| Mutant | Effect | Disposition |
| --- | --- | --- |
| `ofw-resolve/lib.rs:304` delete `"development"` | tighter | kill — table over all six labels |
| `ofw-resolve/lib.rs:306` delete `"staging"` | tighter | kill — same test |
| `ofw-resolve/lib.rs:308` delete `"shared"` | tighter | kill — same test |

### E — Defence-in-depth whose depth was never measured (2 mutants, counted in A)

`tokenize`'s in-loop `tokens.len() > MAX_TOKENS` at `lib.rs:153` can never be
true: `push_token` refuses at `>=` before pushing, so the count never exceeds
`MAX_TOKENS`. The `>` comparison is genuinely unreachable and the two mutants
survive because of it.

They are still killable, and the test that does it is worth having for what it
documents. With a trailing space the final `push_token` runs *inside* the loop,
so the count reaches exactly `MAX_TOKENS` and both `>=` and `==` fire while `>`
does not. The kill therefore records which check is load-bearing — `push_token`'s
— rather than implying line 153 guards a live path.

### F — Diagnostics and provenance (4 mutants)

No decision changes. These matter because the deny reason on stderr is the whole
of what an operator sees, and because the rule identity list is what the audit
record uses to say which rules were in force.

| Mutant | Effect | Disposition |
| --- | --- | --- |
| `ofw-core/lib.rs:269` `Display for ProofError` → empty | diagnostic | kill |
| `ofw-policy/bundle.rs:81` `Display for BundleError` → empty | diagnostic | kill |
| `ofw-resolve/lib.rs:349` `Display for ResolutionError` → empty | diagnostic | kill |
| `ofw-policy/lib.rs:368` `rule_identities` → `vec![]` | diagnostic | kill |

### G — Miscellaneous (3 mutants)

| Mutant | Effect | Disposition |
| --- | --- | --- |
| `ofw-policy/lib.rs:139` `\|\|`→`&&` (empty *or* over-long prefix) | **wider** | kill — an empty prefix matches every path |
| `ofw-resolve/lib.rs:256` `\|\|`→`&&` (empty key *or* value) | **wider** | kill |
| `ofw-resolve/lib.rs:422` `target_count` → `0` / `1` | diagnostic | kill — Milestone 2 binds approvals to this |

## The one real finding

Every other entry above is a missing test. `bundle.rs:239` is not.

`validate_issued_at` indexes `bytes[4]`, `bytes[7]`, `bytes[10]`, `bytes[13]`,
`bytes[16]` and `bytes[18]` directly, and the only thing standing between a
short input and an out-of-bounds panic is a `value.len() < 20` check ten lines
earlier. That check holds in unmutated code, so **this is not a live
vulnerability** — nothing is currently exploitable, and the mutant is killed by
a test that feeds a short timestamp.

It is recorded anyway because of what a panic costs *here* specifically. This
binary is a Codex `PreToolUse` hook, and the host fails **open**: only exit 2
with a correctly shaped reason denies. A panic is exit 101. Any panic on the
decision path is therefore a refusal that silently becomes a pass — the exact
failure mode the whole project exists to prevent. A guard whose correctness
depends on a length check ten lines away is a poor way to hold that line.

The structural fix is to replace the direct indexing with `bytes.get(..)` and
then deny `clippy::indexing_slicing` workspace-wide, which makes the gate
enforce the class rather than this one instance. The workspace already denies
`unwrap_used`, `expect_used` and `panic`; `indexing_slicing` is the member of
that family it does not yet deny, and adding it is consistent with this
project's pattern of giving the gate eyes on the thing rather than trusting a
review.

**Status:** planned in the same change as the tests. This line is updated once
the lint is actually enabled and the workspace is clean under it — not before.

## What this list does *not* say

- It does not say the surviving mutants were harmless. Six are **wider** — a
  bound that stops bounding — and one is **inverted**, which can drop a
  restriction entirely. None was reachable as a bypass in shipped code; all
  seven were unconstrained by any test.
- It does not cover `ofw-cli`, `ofw-adapter-codex`, `ofw-audit` or
  `ofw-contracts`. The mutation job is scoped to the four decision crates, on
  the reasoning recorded in the workflow. Those crates' mutants are unmeasured,
  not clean.
- It does not make criterion 4's mutation gate meaningful on its own. That takes
  flipping the job from advisory to blocking, which only a verified
  zero-survivor state justifies.
