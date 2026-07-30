# Clean-room provenance process

Status: Approved for Milestone 0

## Purpose

This process keeps Operation Firewall independently designed and provides an auditable record for external specifications, examples, fixtures, datasets, reviews, and policy data. It is a process control, not a guarantee that contamination or licensing risk is impossible.

The prohibited comparison project `destructive_command_guard` is a hard boundary: contributors and agents must not inspect, copy, translate, summarize into implementation guidance, mechanically transform, or derive code, tests, documentation, rule data, architecture, or internal patterns from it.

## Allowed source classes

| Class | Permitted use | Record required |
|---|---|---|
| Project-original | Requirements, designs, code, tests, and fixtures created from this repository's threat model and observable safety goals | Contributor attestation; registry entry for material generated datasets |
| Public interface/specification | Normative protocol facts, standards, schemas, and interoperability behavior | Yes, with exact source, access date, terms, and used facts |
| External security review | Findings and questions used to challenge an independently produced design | Yes; findings may influence requirements, not supply copied implementation |
| Third-party fixture/data | Only when license and permitted use are verified | Yes, per artifact or homogeneous set |
| General knowledge | Common algorithms and language/tool documentation | Record when it materially shapes a security control or is reproduced |
| Prohibited/quarantined | Restricted comparison source, unclear-license material, leaked source, or content suspected to cross the boundary | Must not be used; incident record required |

Absence of a license is not permission to copy. Factual public-interface observations may be recorded narrowly for interoperability, with no source text or internal implementation imported.

## Contribution workflow

1. **Declare exposure before work.** A contributor states whether they have viewed the prohibited project or any closely related non-public implementation. Prior exposure does not automatically bar all contribution, but exposed contributors must not design or implement substantially similar internals without maintainer and legal review.
2. **Start from an approved input.** Link the project threat, invariant, user story, standard, or public interface fact that motivates the change.
3. **Classify every external input.** Before importing or adapting anything, assign an allowed source class and verify terms. If terms or provenance are unclear, stop and quarantine the material.
4. **Create a provenance entry.** Add or update `provenance/registry.json` with source identity, access date, source class, terms status, permitted use, artifacts influenced, and an explicit statement of what was not copied.
5. **Design independently.** Write contracts and tests from project invariants. Do not preserve another project's naming, file layout, control flow, rule ordering, fixture values, or test structure merely because it is convenient.
6. **Review the diff for derivation signals.** Review names, comments, data tables, error text, test cases, and module boundaries—not only code similarity.
7. **Validate negative and abuse cases.** Security tests follow the red-first evidence rule: demonstrate that the test fails against a deliberately vulnerable or stubbed implementation before accepting its green result.
8. **Record the review.** The pull request identifies registry entries and includes the contributor attestation below.

## Contributor attestation

Every non-trivial pull request must include:

> I created this contribution from Operation Firewall's approved requirements and the provenance sources listed in this pull request. I did not copy, translate, mechanically transform, or derive implementation, tests, documentation, rules, or internal structure from `destructive_command_guard` or another unlisted source. I disclosed any relevant prior exposure and verified the permitted use of imported material.

AI-assisted contributions use the same attestation. The operator must constrain the model to approved repository context and listed sources; model output is not presumed clean merely because it is generated.

## Registry requirements

Each entry in `provenance/registry.json` includes:

- stable entry ID and date recorded;
- source title, owner/publisher, locator, and access date;
- source class and terms/license status;
- exact permitted use and facts used;
- repository artifacts influenced;
- whether source text, code, tests, fixtures, or data were copied (normally `false`);
- reviewer and review status;
- notes about clean-room separation or prior exposure.

Imported fixtures and policy data require a content digest and a file-level mapping before merge. Generated fixtures record the generating invariant and tool/version when generation is material.

## Contamination response

If a contributor may have crossed the boundary:

1. Stop work and do not further distribute the suspect material.
2. Identify and quarantine exact files/commits without deleting evidence.
3. Open a private provenance incident with source, exposure, affected artifacts, people/models involved, and timestamps. Do not paste restricted content into the incident.
4. Maintainers assess whether removal, independent reimplementation by an unexposed contributor, history rewrite, disclosure, or legal review is required.
5. Reimplementation starts from approved requirements and black-box/public interface facts only, with a fresh provenance record and independent review.
6. No release containing affected material proceeds until the incident is closed by maintainers and legal review where required.

## Enforcement roadmap

Milestone 1 CI should validate registry structure, require provenance references for designated fixture/policy directories, and add a pull-request attestation check. These controls supplement human review; they do not prove originality.
