# Disposition of aramid external review findings

Date: 2026-07-30

Status: Accepted into architecture and milestone gates

This record maps the ranked findings in `2026-07-30-aramid-findings.md` to Operation Firewall decisions. It does not import aramid implementation, tests, configuration, or internal structure.

| Priority | Disposition | Operation Firewall response |
|---|---|---|
| 1. Monotonic policy merge | Accepted; Milestone 0 resolved | ADR 0002 chooses an enforced hard floor. Policy is a union of restriction-only rules, not an overlay. Repository policy cannot express grant, deletion, waiver, priority, or replacement. Property, mutation, and permutation proof obligations are mandatory. |
| 2. Prove security tests red | Accepted immediately | PRD, architecture, and test strategy require red-first evidence from Milestone 0. Contract negative fixtures include executable deliberate-weakening witnesses. |
| 3. Adversarially review decision logic | Accepted as Milestone 1→2 gate | Architecture and the production definition of done require a distinct adversarial design review before approval capabilities are accepted. |
| 4. Out-of-hot-path coverage | Accepted for Milestone 1/2 | Architecture defines independent reconciliation of host-observed tool calls against decision/audit IDs. It reports coverage health but cannot undo effects. |
| 5. Approval hardening | Accepted as fixed requirement | FR-036 prohibits non-cryptographic fallback. FR-037 requires atomic single-use redemption with exactly one concurrent success. |
| 6. Concurrent state mutation | Accepted in test foundations | Policy activation is atomic and immutable-snapshot based; approval redemption concurrency is a Milestone 2 exit criterion. |
| 7. Living critical corpus | Accepted | Test strategy requires every confirmed new bypass to become a permanent provenance-linked regression case. |
| 8. Bake then arm | Accepted for post-launch policy rollout | Architecture requires warn-only simulation, measurement/tuning, and explicit audited activation. Simulation cannot weaken an existing restriction. |

No finding is treated as proof that the resulting system is complete or bypass-proof. Host fail-open behavior, unavailable coverage, novel operation encodings, and implementation defects remain residual risks requiring measurement and review.
