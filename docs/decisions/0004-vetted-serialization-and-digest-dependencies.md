# 4. Vetted serialization and digest dependencies

Date: 2026-08-07

## Status

Accepted.

## Context

The workspace has carried zero runtime dependencies since Milestone 0. That was
never a permanent constraint — the Milestone 1 completion design names `serde`,
`serde_json`, `sha2`, and a cross-platform file-locking crate as the approved
runtime dependency set — but the design also requires that each crate be
validated **before** `Cargo.toml` is modified, with the evidence recorded. No
such record existed, so no dependency could legitimately be added, and the
absence of a validation record was the actual blocker rather than the principle.

Three pieces of Milestone 1 cannot be built without it:

- **v1 contract deserialization.** Policy bundles are untrusted input read from
  disk. The contracts are JSON Schema Draft 2020-12 and must be parsed with
  unknown-field rejection.
- **Audit event construction.** Records are canonically serialized before
  digesting and appending.
- **Digests.** `AgentInvocation` carries a digest of the raw request rather than
  the request, and audit records carry digests instead of payload bodies.

The alternative — hand-writing a general strict JSON parser — was considered and
rejected. The existing hand-written parser in `ofw-adapter-codex` is justified by
a narrow, fixed, fully enumerated envelope shape. A general parser for five
evolving schemas is a materially larger attack surface written by one author and
exercised only by this project's own tests, against a parser exercised by a
billion downloads and a decade of fuzzing. Preferring the smaller *audited*
surface over the smaller *authored* surface is the same reasoning the threat
model applies elsewhere.

## Validation evidence

Gathered from the crates.io registry API and `cargo info` on 2026-08-07, before
any `Cargo.toml` change.

| | `serde` | `serde_json` | `sha2` |
| --- | --- | --- | --- |
| Version | 1.0.229 | 1.0.151 | 0.11.0 |
| Licence | MIT OR Apache-2.0 | MIT OR Apache-2.0 | MIT OR Apache-2.0 |
| Minimum Rust | 1.56 | 1.71 | 1.85 |
| Owners | `dtolnay`, `github:serde-rs:publish` | `dtolnay`, `github:serde-rs:publish` | `tarcieri`, `newpavlov`, `github:rustcrypto:hashes` |
| Repository | serde-rs/serde | serde-rs/json | RustCrypto/hashes |
| First published | 2014-12-05 | 2015-08-07 | 2016-05-06 |
| Latest release | 2026-07-18 | 2026-07-20 | 2026-03-25 |
| Downloads | 1,240,654,534 | 1,144,809,207 | 815,247,607 |

**Spelling.** Each name was resolved through the registry API by exact name and
returned the expected repository and owner set. None is a near-miss of a more
popular crate: `serde`, `serde_json` and `sha2` are themselves the popular
names, which is the direction that makes typosquatting a risk to *us* rather
than a risk *from* us. The registry-reported repository for each matches the
upstream organisation the crate is known by.

**Ownership and maintenance.** Both serde crates are published by the same
individual owner and publish team. `sha2` is published by the RustCrypto
organisation with two individual owners. All three have releases within the last
five months, and all three predate this project by roughly a decade. Owner
concentration on the serde crates is a real single-maintainer risk and is
recorded as a residual below rather than treated as absent.

**Licensing.** All three are `MIT OR Apache-2.0`, compatible with this project's
MIT licence. No copyleft, no source redistribution obligation.

**Minimum supported Rust.** The highest requirement is `sha2` at 1.85. The
pinned toolchain is 1.97.1, so no crate forces a toolchain change.

**Necessity.** Each maps to a named Milestone 1 deliverable and none is a
convenience: `serde`/`serde_json` to contract deserialization and canonical
audit serialization, `sha2` to the digests that let audit records and the
invocation boundary carry evidence instead of payloads.

## Feature surface

Features are chosen to *reduce* surface, not for convenience. The exclusions are
the security-relevant part of this decision:

- **`serde`: `derive` only.** No `rc` (which would allow deserializing into
  reference-counted containers and can surprise on aliasing), no `unstable`.
- **`serde_json`: default features only.** Three defaults-off features are
  deliberately left off:
  - **`unbounded_depth` stays off.** With it off, `serde_json` enforces a
    recursion limit of 128 while parsing. Policy bundles are untrusted input
    read from a repository, and deeply nested JSON is a stack-exhaustion vector.
    This is the single most important feature decision here, and it is a
    decision to keep a default rather than to add anything.
  - **`arbitrary_precision` stays off.** It changes number representation and
    has historically interacted badly with `deny_unknown_fields` and untagged
    enums. The contracts use bounded integers.
  - **`preserve_order` stays off.** It would pull `indexmap` into the trusted
    runtime for a property the contracts do not need; canonical ordering is the
    project's own concern under RFC 8785.
- **`sha2`: `default-features = false`.** Drops `oid`, which carries ASN.1
  object-identifier metadata this project has no use for.

## Decision

Adopt `serde` (with `derive`), `serde_json`, and `sha2` as runtime dependencies,
added to the crate that consumes each and no wider. `Cargo.lock` is committed and
CI builds `--locked`, so the resolved graph is pinned and a change to it is a
reviewable diff rather than a silent upgrade.

`cargo audit` runs in CI against the advisory database. The resolved dependency
tree and the advisory result are recorded in this document's addendum below,
after the first successful build, because a resolved tree is stronger evidence
than a pre-resolution prediction.

The zero-dependency property is therefore **deliberately ended, not lost**. What
replaces it is a small, pinned, licence-compatible, advisory-scanned set with
the expansion-prone features switched off.

## Consequences

- `ofw-adapter-codex` keeps its hand-written envelope parser. It is not
  rewritten onto `serde_json`: the Codex envelope is a fixed shape on the
  fail-open hot path, and replacing working, fuzz-shaped code carries more risk
  than it removes. The two parsers coexist by design and that is recorded here
  so it does not read as an oversight.
- `#![forbid(unsafe_code)]` remains correct for this project's own crates. It
  constrains the crates in this workspace, not dependencies, and none of these
  three requires unsafe code from us.
- A future file-locking crate for audit persistence, and any platform bindings
  for resolver evidence, require their **own** entry in this process. This
  decision does not pre-approve them. Platform bindings in particular would need
  `unsafe` in our own code and therefore conflict with the workspace `forbid`,
  which is an open design question and not a settled one.

## Residual risks

- **Single-maintainer concentration.** Compromise of the serde publish path
  would reach this project. The mitigation available today is the committed
  lockfile plus `--locked` CI, which converts a malicious upstream release into
  something that cannot enter without a visible lockfile diff. Vendoring is
  available if the risk assessment changes.
- **Advisory lag.** `cargo audit` reports known advisories, not unknown ones.
- **Transitive surface.** The resolved tree is recorded in the addendum. Growth
  in that tree on a future upgrade is a reviewable event, not an automatic one.

## Addendum: resolved tree and advisory status

Recorded 2026-08-07 after the first successful build. `sha2` is **not** in the
tree yet: it is reviewed above but is only added when the audit crate that needs
it lands, because a dependency should not enter the lockfile before the code
that consumes it.

Eleven third-party crates resolve:

| Crate | Version | Role |
| --- | --- | --- |
| `serde` | 1.0.229 | Deserialization traits |
| `serde_core` | 1.0.229 | serde's own core split |
| `serde_derive` | 1.0.229 | Derive macros (build-time) |
| `serde_json` | 1.0.151 | JSON |
| `itoa` | 1.0.18 | Integer formatting |
| `memchr` | 2.8.3 | Substring scanning |
| `zmij` | 1.0.23 | Float formatting |
| `proc-macro2` | 1.0.107 | Macro support (build-time) |
| `quote` | 1.0.47 | Macro support (build-time) |
| `syn` | 3.0.3 | Macro support (build-time) |
| `unicode-ident` | 1.0.24 | Identifier classification (build-time) |

`cargo audit` scanned 18 crate dependencies against 1,190 advisories and exited
0 with no vulnerable package.

### One transitive crate worth naming

`zmij` was not predicted by this review and is the kind of thing the review
exists to surface. It is `serde_json`'s float-formatting dependency — a
Schubfach implementation, effectively the successor to `ryu` — published by
`dtolnay`, the same owner as both serde crates, at 303 million downloads.

Two things about it are worth recording rather than waving through:

- It is **young**: first published 2025-12-18, roughly eight months old, against
  a decade for everything else in this set.
- Its licence is **MIT only**, not the `MIT OR Apache-2.0` of the rest.
  Compatible with this project, but it is the one crate here without the dual
  option.

Most importantly, it does not diversify the single-maintainer risk noted above
— it **concentrates** it. Four of the eleven resolved crates now share one
publisher. The mitigation is unchanged and still adequate: the lockfile is
committed and CI builds `--locked`, so nothing from that publisher enters
without a reviewable diff. It is recorded here so that a future reader weighing
that risk is counting four crates and not two.
