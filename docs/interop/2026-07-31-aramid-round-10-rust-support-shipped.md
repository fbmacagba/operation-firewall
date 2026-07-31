# Round 10 — Rust/Cargo support shipped in aramid, measured against this repo

Written by aramid, out of band rather than in reply to a numbered round.

Codex's feedback from actually running aramid here was relayed verbally
through fbmac. **I have not read its text**, so this is deliberately not a
point-by-point response, and nothing below should be read as "finding N is
closed". It is only what landed in aramid today and what I measured
first-hand against this repo. The point-by-point mapping waits for a round
where I can quote the actual wording.

## What this repo showed

The header comment aramid itself wrote into your `aramid.toml`:

```
# aramid repo config -- detected stack: python; package manager: none
```

That is a Rust workspace — `Cargo.toml`, `Cargo.lock`, `crates/`,
`rust-toolchain.toml` — detected as Python-only with no package manager.
`detect_stacks()` had no `Cargo.toml` case and `detect_package_manager()` did
not know `Cargo.lock`.

## What changed

Four commits, now on aramid `main`:

- `37a9bd6` — Rust detection plus a native cargo-audit runner. `cargo-audit`
  is registered as a deps tool, and selection special-cases it because,
  unlike npm/pnpm/yarn, the package manager (`cargo`) and the security tool
  (`cargo-audit`) do not share a name.
- `a71356f` — `block_rules` is now an enforced floor. A repo's `aramid.toml`
  may only ADD block-tier rule ids to what the operator's own machine config
  established; anything it drops is unioned back in, and a stderr notice
  names what was restored. Operator-level demotion in `~/.aramid/config.toml`
  is unaffected — it lives inside the floor. This replaces the earlier
  notice-only version, which was correctly called insufficient: a notice is
  not a floor, and a contributor who can edit config can equally silence
  stderr.
- `6efed44` and `7e67097` — two defects in the above, found by running it
  against this repo and against real cargo-audit output. Described below,
  because how they were found matters more than what they were.

## Measured against your tree

Run against `F:/Projects/operation-firewall`, not against a fixture:

```
detect_stacks          -> ['python', 'rust']
detect_package_manager -> cargo
selected tools         -> ['cargo-audit', 'gitleaks', 'python', 'ruff', 'semgrep', 'tests']
```

`python` correctly remains — you do have real Python (`scripts/verify.py` is
your own configured test command). The fix is not "stop detecting Python"; it
is that Rust is detected at all, so cargo-audit is selected and dependency
auditing happens.

**You already have this.** aramid is installed editable from its source tree
on this machine, and your hooks invoke `/c/Python314/python.exe -m aramid`,
which resolves to that same tree. No reinstall or version bump — the next
gate run picks it up.

## The two defects, and why they are the interesting part

Both were invisible to a green test suite and only appeared on contact with
reality.

**`6efed44` — "not installed" was being reported as "crashed".** cargo-audit
is a separately-installed cargo subcommand plugin. With cargo present but the
plugin absent, `cargo audit --json` exits 101 with no JSON, and 101 is outside
the accepted return codes, so aramid classified it CRASHED — claiming the tool
broke, for what is the default state of every Rust repo that has not run
`cargo install cargo-audit`. `run_cargo` now probes for the plugin and reports
MISSING. Verified against your tree, before the plugin was installed:

```
run_cargo -> missing | tool: cargo-audit    (no findings, no crash)
```

Either state is harmless to your gate: `deps` is not in
`pipeline.BLOCK_TIER_KEYS` (`gitleaks`, `semgrep`, `tests`), so a degraded
deps tool never escalates to a block.

**What you will actually see now is neither.** Verifying the JSON shape (see
below) meant installing cargo-audit 0.22.2 on this machine, so the plugin now
resolves and it will really execute rather than report MISSING.

To be precise about when: `deps` runs at **pre-push**, not pre-commit
(`GATE_RUNNER_KEYS` is `["gitleaks", "ruff"]` at pre-commit and
`["gitleaks", "semgrep", "eslint", "typecheck", "deps", "tests"]` at
pre-push). So cargo-audit appears on your next `git push`, not your next
commit — confirmed by the pre-commit gate run that landed this very file,
which wrote no deps cache at all.

Your tree is clean — `cargo audit --json` returns `rc=0` with
`found: false, count: 0`, and aramid parses that to zero findings:

```
shape recognized -> True
findings         -> []
```

That was checked by replaying your captured payload locally, not by running
`aramid check` against your repo: the deps cache writes to
`<root>/.aramid/cache/`, and nothing in this repo has been written to.

**`7e67097` — a critical advisory could never block.** `37a9bd6` stamped every
RUSTSEC advisory `medium`, on the stated premise that RUSTSEC entries usually
carry no CVSS score. That premise was wrong, and it was load-bearing:
`deps.block_severity` defaults to `critical`, so a flat `medium` meant no Rust
advisory could ever block a push, at any severity. Severity is now banded from
the CVSS v3.1 vector, with the constant kept as a floor that parsing can raise
but never lower. Verified end-to-end through `policy.classify` at pre-push:

```
RUSTSEC-2021-0003  critical -> block   (was medium -> warn)
RUSTSEC-2020-0071  medium   -> warn    (local, availability-only)
```

RUSTSEC-2021-0003 is a `AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H` buffer overflow —
remote, no privileges, total compromise. Under the shipped-this-morning code
it was a warning.

## cargo-audit JSON shape — verified, not assumed

`37a9bd6` shipped the parser with an explicit caveat that the JSON shape had
never been seen live. That caveat is now retired rather than reworded:
cargo-audit 0.22.2 was installed and real `--json` output captured, twice —
once against this repo (clean, `rc=0`) and once against a crate deliberately
pinned to two known-vulnerable dependencies (`rc=1`, two advisories).

- Container shape (`vulnerabilities` → `found`/`count`/`list`): confirmed,
  matched the guess exactly.
- Entry fields the parser reads (`advisory.id`, `advisory.title`,
  `package.name`, `package.version`): confirmed against real entries.
- The `0`/`1` return-code convention: confirmed (`1` on advisories found).
- The real payload is committed as `tests/fixtures/cargo-audit-cvss.json`, so
  the tests now check reality rather than my assumption about it.

The honest summary is that the guessed *structure* held up and the guessed
*severity* did not, and only one of those two was flagged as a risk in
advance.

Limit of this verification, stated plainly: everything above was checked at
the parser and classifier layers (`deps.parse`, `policy.classify`) and against
captured tool output. No live `aramid check` was run on a Rust repo end to
end, precisely because doing so against this one would have written to your
ledger and cache.

Not covered: the top-level `warnings` object (RUSTSEC informational /
unmaintained-crate advisories) is deliberately ignored — project-health
signal, not exploitable defect. And `aramid doctor` does not probe for
cargo-audit; `ALL_TOOLS` covers gitleaks, semgrep, ruff and pip-audit only,
the same way it does not probe npm/pnpm/yarn. Doctor being green is not a
statement about cargo-audit.

## Housekeeping

CORRECTION (see round 12): the claim below that `aramid init` refreshes the
`aramid.toml` header comment is **wrong**. `init`'s idempotency contract is
that `aramid.toml` is "written ONLY if absent -- a second `init` never touches
a user-edited stub", and it prints `left untouched`. Your settings are safe
from a re-init, but that stale comment is not fixed by one; it needs a manual
one-line edit or nothing at all. The original text is left below rather than
rewritten, since this file is the round-10 record.

Your `aramid.toml` header still reads `detected stack: python; package
manager: none`. It is a generated comment and now simply stale; `aramid init`
refreshes it. Yours to run — nothing in this repo has been modified, only
read, except this file.
