# Round 17 — Rust security rules: the gap round 16 left open

Written by aramid. Code: aramid `c748d61` (full unit+integration suite:
1298 passed, 4 skipped).

Round 16 closed point 1 for *gate discovery* and said plainly what was still
missing:

> semgrep still has zero Rust rules. clippy is a correctness/style linter,
> not a security scanner, and there is no bandit-equivalent ruleset for Rust
> the way ruff's S-rules serve Python.

That is now closed too.

## Six rules, each verified firing

| rule | tier | CWE |
|---|---|---|
| `owasp-top-ten.a03-injection.rust-command-injection-shell-spawn` | **BLOCK** | CWE-78 |
| `owasp-top-ten.a03-injection.rust-sqli-format-string` | **BLOCK** | CWE-89 |
| `rust-memory-safety.transmute` | WARN | CWE-704 |
| `rust-memory-safety.from-utf8-unchecked` | WARN | CWE-119 |
| `rust-memory-safety.get-unchecked` | WARN | CWE-125 |
| `rust-memory-safety.set-len` | WARN | CWE-908 |

Every one was run against real vulnerable Rust before shipping, and — more
importantly — against its safe counterpart. A rule that flags correct code is
worse than no rule, because it trains people to ignore the gate.

Verified silent: an all-literal shell string
(`Command::new("sh").arg("-c").arg("ls -la")`), a direct argv invocation
(`Command::new("ls").arg(user)`), bound sqlx parameters, and
`from_utf8`/`get`/`resize`.

## Why two namespaces, and why that is the whole design

In aramid, **the semgrep namespace IS the tier.** `block_rules.toml` blocks
`owasp-top-ten.*` wholesale, so anything placed there blocks a push once
semgrep is armed.

- **Injection rules belong there.** Rust's memory safety does not extend to
  what it hands an interpreter: a shell or a SQL engine parses
  attacker-controlled text exactly as unsafely as it does from Python or JS.
  These mirror the existing Python/JS injection rules one-for-one, so they
  get the same tier those have always had.
- **The memory-safety lints must not.** They are the closest Rust analogue to
  ruff's bandit S-rules — operations that opt out of the guarantees the rest
  of the language provides — but `transmute` and `get_unchecked` are
  legitimate in FFI and perf-critical code. Shipping them as BLOCK would be
  precisely the noisy-BLOCK trap `ARAMID.md` warns about, and the fastest way
  to get an operator to demote the whole tool.

An operator who *wants* them blocking promotes them via `block_rules`, and
under the round-11 floor a repo can only ever ADD to that, never remove.

Verified end to end through `policy.classify` with
`semgrep_block_armed = true`:

```
block  high     owasp-top-ten.a03-injection.rust-command-injection-shell-spawn
block  high     owasp-top-ten.a03-injection.rust-sqli-format-string
warn   medium   rust-memory-safety.transmute
warn   medium   rust-memory-safety.get-unchecked
```

## A latent bug the second namespace exposed

Adding a namespace was not free, and this is worth recording because it is
the same shape as several findings in this thread.

`_canonical_rule_id` normalises semgrep's live `check_id` — which carries the
**config file's path**, dot-joined — back to the canonical rule id that
`block_rules`, overrides and suppressions are all written against. It stripped
exactly one prefix, `owasp-top-ten.`, and returned anything else unchanged.

So a rule in any new namespace would have kept a prefix like
`F.Projects.aramid.src.aramid.rules.` — an **absolute path from the machine
that ran the scan**. Rule ids, and every fingerprint, override and suppression
keyed on them, would have differed per checkout. Silent, and only visible once
a second machine ran the same scan.

Fixed first, then the rules were added on top: normalisation is now driven by
`VENDORED_RULE_PREFIXES`, with the existing rightmost-occurrence guarantee
unchanged (a checkout path that itself embeds a namespace literal must not
truncate the real id early).

## What this means for this repo

`semgrep_block_armed = false` here, so all six arrive as WARN during your bake
period regardless of tier — visible, non-blocking, exactly as your ADR 0002
disposition describes. When you arm semgrep, the two injection rules become
blocking and the four memory-safety lints stay advisory.

Worth a specific note given your threat model: `ofw-policy` and
`ofw-contracts` both set `#![forbid(unsafe_code)]`, so the memory-safety lints
should find nothing there by construction — and if one ever fires, that is
itself the signal, because it means the forbid was removed or a new crate
arrived without it.

## Honest remaining scope

Six rules is a starting set, not parity with a mature Rust security ruleset.
Not covered: path traversal, SSRF, unsafe deserialization sinks specific to
Rust crates, weak crypto construction, and `unsafe` block auditing beyond the
four operations above. cargo-audit covers known-CVE dependencies; these cover
code aramid can see. The gap between "has Rust security rules" and
"comprehensive Rust security coverage" is real, and I would rather name it
than let the table above imply otherwise.
