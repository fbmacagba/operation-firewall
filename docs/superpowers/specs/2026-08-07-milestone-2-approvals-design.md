# Milestone 2 design — bound approvals, replay protection, revalidation

**Status: draft, not approved. No code implements this.**

Written 2026-08-07 at the operator's direction, on the explicit basis that
building approval and replay mechanisms without a reviewed design is the thing
this project is most careful not to do. Milestone 1 was defensible because its
design was approved first; this document exists so Milestone 2 can be judged the
same way, and it should be read adversarially before anything here is built.

## Why this milestone exists

Milestone 1 can decide. It cannot **remember a decision**, and it cannot stop a
decision being reused for something else. Today the pipeline reaches
`DecisionOutcome::Ask` for every interpreted git read and then denies, because
an ask that nobody can answer is not an approval. That is honest and it is also
the ceiling: no operation reaches `allow`, so the tool is a very careful refuser.

Milestone 2 is what turns an `ask` into a decision a human actually made. Every
mechanism below exists to make one sentence true:

> An approval authorises exactly one operation, against exactly the targets that
> were resolved when it was granted, exactly once, and only for as long as the
> world has not changed underneath it.

Each clause of that sentence maps to a mechanism, and each mechanism has a
failure mode that reintroduces the whole problem.

## What Milestone 1 already provides

- `RevalidationFingerprint` (shipped 2026-08-07). Operation kind, grammar
  revision, boundary digest, target count, and a length-prefixed digest of the
  sorted canonical target set, plus a single `digest()` over all of it.
- `revalidate(recorded, current) -> Revalidation`, which destructures the
  fingerprint so a field added later cannot be silently left out of the
  comparison.
- A structurally redacted audit record with no field that can hold a payload.
- A decision core where `allow` requires a proof and policy can only restrict.

The fingerprint is the join point. **An approval binds to `fingerprint.digest()`
and to nothing else** — not to a command string, not to a session, not to a path
list. Binding to a command string would authorise a *spelling*, and two
spellings can resolve to different files.

## The threat model this milestone must survive

Milestone 1's threat model assumed an agent proposing operations. Approvals add
a stored credential, and a stored credential invites attacks Milestone 1 has no
equivalent of.

| # | Attack | Mechanism that must stop it |
| --- | --- | --- |
| T1 | Redeem an approval for a different operation | Binding to the fingerprint digest |
| T2 | Redeem the same approval twice | Single-use redemption, replay state |
| T3 | Redeem after the targets changed | Pre-execution revalidation |
| T4 | Redeem long after the human's intent expired | Expiry |
| T5 | Forge an approval | Signature over the bound fields |
| T6 | Strip or downgrade the signature | Typed verification, no unsigned path |
| T7 | Redeem an approval granted to another session or user | Actor and session binding |
| T8 | Roll the replay store back to un-redeem | Monotonic, append-only, fail-closed |
| T9 | Race two redemptions of one approval | Exclusive lock around check-and-mark |
| T10 | Grant approval for a *class* of operations | No wildcards, ever |

T8 and T9 are the ones most often got wrong, and both are storage properties
rather than cryptography properties. An approval system with perfect signatures
and a replay store that loses writes is not a replay-protected system.

## Design

### Approval token

```
ApprovalToken {
  schema_version
  approval_id            // unique, and the replay key
  fingerprint_digest     // what is authorised. THE binding.
  actor_ref, session_ref // digests, as in the audit record
  granted_at, expires_at // absolute, RFC 3339, monotonic-checked at redemption
  grammar_revision       // refuse a token from an interpreter we are not
  signature              // over the canonical encoding of every field above
}
```

Encoding uses the same **length-prefixed framing** as the fingerprint. A
signature over separator-joined fields is a signature over an ambiguous string,
which is the same defect the fingerprint witness already retains.

There is deliberately **no scope field, no wildcard, no count**. An approval is
for one operation. "Approve all reads in this directory for an hour" is a policy
rule, and policy is restriction-only by construction — it can never grant. If
that capability is ever wanted it needs its own design and its own threat model.

### Redemption

Redemption is one function with no partial success:

1. Verify the signature. Unverifiable ⇒ `Indeterminate`.
2. Check `grammar_revision` matches this build's. Mismatch ⇒ `Indeterminate`.
3. Check expiry against a monotonic reading. Expired ⇒ `Indeterminate`.
4. Recompute the fingerprint **now**, from a fresh resolution.
5. `revalidate(token.fingerprint, current)`. Anything but `Unchanged` ⇒
   `Indeterminate`, reporting which field changed.
6. Under an exclusive lock: consult the replay store; if `approval_id` was seen,
   ⇒ `Indeterminate`; otherwise mark it seen, durably, and only then return
   `Allow`.

Step 6's ordering is the whole of replay protection. **Mark before returning,
never after acting.** A crash between returning `Allow` and recording the
redemption leaves an approval that can be redeemed again, and a crash between
marking and returning merely costs the user a re-approval. The asymmetry is the
same one the audit gate already makes: losing an action is recoverable, losing
the record of it is not.

### Replay store

An append-only file under the audit directory, with the same exclusive locking
and crash-recovery behaviour `AuditSink` already implements — including
quarantining a damaged trailing record rather than reading it.

Fail-closed and specifically: **an unreadable, missing, or damaged replay store
makes every redemption `Indeterminate`.** Not "allow, we cannot check" and not
"allow, it is probably fine". This is the exact shape of the `NoRestriction`
advisory that criterion 6 exists for — an absence of evidence read as evidence of
absence — and it will be tempting to soften it the first time an operator is
locked out by a full disk.

Retention has the same problem audit retention has and gets the same answer for
now: **not implemented**. Pruning redeemed approvals is deleting the evidence
that stops replay, and an approval older than its expiry is refused by step 3
anyway, so the store can be pruned by expiry *if and only if* the expiry check is
proven to run first. That proof does not exist yet.

### Signing keys

Out of scope for the first slice, and this is a deliberate staging rather than an
oversight. The first slice uses a **local key with no rotation**, and `doctor`
must report `key_management: not_implemented` — because a deployment that
believes it has key rotation and does not is worse off than one that knows it
does not.

## Red-first witnesses this milestone must retain

Each of these must exist and fail against the weakened form, on the pattern
Milestone 1 established:

- an approval redeemed against a different fingerprint;
- an approval redeemed twice (the second must fail);
- an approval redeemed after a target file was replaced;
- an expired approval redeemed;
- an approval with a stripped or altered signature;
- an approval redeemed with the replay store unreadable (must not allow);
- a redemption that marks the store *after* returning allow;
- two concurrent redemptions of one approval (exactly one may succeed);
- an approval granted under a different grammar revision.

The concurrency one needs real processes and a real filesystem lock, as the
audit concurrency test already does — threads through one in-process lock would
prove the lock works, not that the store does.

## What this milestone still will not deliver

Even fully built, this does not make the production claim available on its own.
The design's completion criteria also require a **verified live host
integration**: `ofw` registered as a real Codex `PreToolUse` hook, observed
allowing and denying real tool calls. That cannot be done from inside this
repository — it needs a Codex configuration outside it — and it is the operator's
action to authorise, not this project's to assume.

## Open questions for review

1. Should an approval bind `actor_ref`/`session_ref` as *required* match
   criteria, or record them for audit only? Binding is stricter and breaks any
   workflow where the approver and the actor differ.
2. What is a defensible default expiry? Too long defeats the point; too short
   trains operators to approve reflexively, which is worse than no approval.
3. Should redemption be a separate `ofw approve` subcommand, or inline in the
   hook path? Inline keeps the deadline budget honest; separate keeps the hook
   path free of a writable store.
4. Is a local unrotated key acceptable for a first slice at all, or does that
   make the mechanism misleading enough to be worth delaying?

Nothing here should be built until at least 1 and 4 are answered.
