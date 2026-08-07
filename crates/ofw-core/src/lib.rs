#![forbid(unsafe_code)]

//! Built-in safety baseline and final decision composition.
//!
//! `ofw-policy` is restriction-only by construction: its `Restriction` type has
//! no `allow` variant, so no policy layer can express a weakening. The
//! consequence is that policy alone can never authorize anything -- it can only
//! preserve or increase restriction. Something else has to establish that an
//! operation is understood and safe enough to permit, and that is
//! [`SupportedOperationProof`].
//!
//! `PolicyOutcome::NoRestriction` means only that policy added nothing. Mapping
//! it directly to allow is the vulnerability this crate exists to prevent:
//! it would authorize every operation no rule happened to mention, including
//! operations the system does not understand at all.

use ofw_contracts::{
    BlastRadius, EnvironmentClass, NamespacedName, OperationEffect, Reversibility, Version,
};
use ofw_policy::{PolicyEvaluation, PolicyOutcome};

/// The strength of the built-in baseline, ordered `Allow < Ask < Deny`.
///
/// The ordering is load-bearing: [`decide`] joins the baseline with the policy
/// restriction using [`Ord::max`], so reordering these variants would silently
/// invert the join. `baseline_restriction_ordering_is_pinned` guards it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BaselineRestriction {
    Allow,
    Ask,
    Deny,
}

/// The final decision for one operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DecisionOutcome {
    Allow,
    Ask,
    Deny,
    Indeterminate,
}

/// Whether the operation reaches an execution surface outside the decision
/// core's closed grammar.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExecutionSurface {
    None,
    Present,
}

/// Whether every target of the operation was resolved.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetCompleteness {
    Complete,
    Incomplete,
}

/// Whether every target lies inside the configured repository boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Containment {
    RepositoryLocal,
    CrossBoundary,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PrivilegeRequirement {
    Standard,
    Elevated,
    SecurityControl,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Publication {
    NotApplicable,
    Safe,
    Unsafe,
}

/// Evidence about one recognized operation.
///
/// # Trust boundary
///
/// These fields are **trusted inputs, not proofs**. Establishing that
/// `containment` really is `RepositoryLocal`, that `execution_surface` really
/// is `None`, or that a publication really is `Safe` is the platform
/// resolver's job, and the resolver is a later Milestone 1 slice. Until it
/// lands, a [`SupportedOperationProof`] is exactly as trustworthy as whoever
/// constructed its evidence.
///
/// What this type does guarantee is narrower and still worth having: the
/// baseline *verdict* is derived from the evidence rather than accepted from
/// the caller, so a caller cannot simply assert `allow`. Agent- or
/// repository-supplied labels must never reach these fields directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationEvidence {
    pub grammar_revision: Version,
    pub operation_kind: NamespacedName,
    pub effect: OperationEffect,
    pub execution_surface: ExecutionSurface,
    pub target_completeness: TargetCompleteness,
    pub containment: Containment,
    pub privilege: PrivilegeRequirement,
    pub publication: Publication,
    pub reversibility: Reversibility,
    pub blast_radius: BlastRadius,
    pub environment: EnvironmentClass,
}

/// Typed evidence that one operation was recognized completely enough to be
/// given a baseline.
///
/// A value of this type cannot exist for an operation with unknown or
/// incomplete evidence: [`SupportedOperationProof::new`] rejects those, which
/// is how the baseline matrix's `indeterminate` row is enforced. Combined with
/// [`decide`] returning `Indeterminate` for an absent proof, an unproven
/// operation has no path to allow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedOperationProof {
    evidence: OperationEvidence,
}

impl SupportedOperationProof {
    /// Rejects evidence that does not establish a proven operation.
    ///
    /// Each rejected case is the matrix's "unknown, incomplete, ambiguous"
    /// row. Returning an error here rather than a weak baseline keeps the
    /// unproven case unrepresentable instead of merely discouraged.
    pub fn new(evidence: OperationEvidence) -> Result<Self, ProofError> {
        if matches!(evidence.target_completeness, TargetCompleteness::Incomplete) {
            return Err(ProofError::IncompleteTargets);
        }
        if matches!(evidence.effect, OperationEffect::UnknownMutation) {
            return Err(ProofError::UnknownEffect);
        }
        if matches!(evidence.reversibility, Reversibility::Unknown) {
            return Err(ProofError::UnknownReversibility);
        }
        if matches!(evidence.blast_radius, BlastRadius::Unknown) {
            return Err(ProofError::UnknownBlastRadius);
        }
        if matches!(evidence.environment, EnvironmentClass::Unknown) {
            return Err(ProofError::UnknownEnvironment);
        }
        Ok(Self { evidence })
    }

    #[must_use]
    pub fn evidence(&self) -> &OperationEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn operation_kind(&self) -> &NamespacedName {
        &self.evidence.operation_kind
    }

    #[must_use]
    pub fn grammar_revision(&self) -> &Version {
        &self.evidence.grammar_revision
    }

    /// Derives the built-in baseline from recorded evidence.
    ///
    /// The caller supplies evidence and never the verdict: a baseline accepted
    /// from a caller would be a forgeable authorization primitive, which the
    /// threat model names directly (a malicious repository or a prompt-injected
    /// agent asserting that its own operation is safe).
    #[must_use]
    pub fn baseline(&self) -> BaselineRestriction {
        let evidence = &self.evidence;

        // Deny is tested first and the order is load-bearing. Several
        // operations satisfy a deny row and an allow row at the same time --
        // a bounded, non-executing read *of a security control* is the clearest
        // case. Testing the allow rows first would let the weaker row win.
        // `red_first_witness_detects_permissive_derivation_order` retains that
        // inversion and proves it flips such a case to allow.
        if matches!(
            evidence.privilege,
            PrivilegeRequirement::Elevated | PrivilegeRequirement::SecurityControl
        ) || matches!(evidence.containment, Containment::CrossBoundary)
            || matches!(evidence.publication, Publication::Unsafe)
            // Execution and permission change are denied on the effect alone.
            // The design doc excludes general-purpose command safety
            // classification from this milestone, so no execution can be
            // *proven* safe here; deriving anything weaker would rest on a
            // caller-supplied privilege label.
            || matches!(
                evidence.effect,
                OperationEffect::Execute | OperationEffect::PermissionChange
            )
            || (matches!(evidence.effect, OperationEffect::Delete)
                && matches!(
                    evidence.blast_radius,
                    BlastRadius::Broad | BlastRadius::Unbounded
                ))
        {
            return BaselineRestriction::Deny;
        }

        // Three deliberate tightenings of the published allow rows, none of
        // which the design doc's table states. All narrow what may be allowed,
        // and policy composition can only add restriction, so none can be
        // undone downstream:
        //   - an allow baseline requires a low-consequence environment;
        //   - an allow baseline requires a bounded blast radius;
        //   - an allow baseline requires no reachable execution surface.
        let low_consequence_environment = matches!(
            evidence.environment,
            EnvironmentClass::Local | EnvironmentClass::Development | EnvironmentClass::Test
        );
        let bounded = matches!(
            evidence.blast_radius,
            BlastRadius::Single | BlastRadius::Bounded
        );

        // No allow row survives a reachable execution surface. Hoisted out of
        // the individual rows so a row added later cannot omit it: the
        // condition belongs to "may be allowed at all", not to any one row.
        // A command that consults repository-controlled configuration can name
        // further programs to run whatever it does to the target it names, so
        // this binds a write at least as tightly as a read.
        let no_execution_surface = matches!(evidence.execution_surface, ExecutionSurface::None);

        if low_consequence_environment && bounded && no_execution_surface {
            // Bounded metadata/read.
            if matches!(evidence.effect, OperationEffect::Read) {
                return BaselineRestriction::Allow;
            }
            // Bounded reversible repository-local edit with complete targets.
            // Target completeness is guaranteed by the constructor.
            if matches!(
                evidence.effect,
                OperationEffect::Create | OperationEffect::Update
            ) && matches!(evidence.reversibility, Reversibility::Reversible)
                && matches!(evidence.containment, Containment::RepositoryLocal)
            {
                return BaselineRestriction::Allow;
            }
        }

        // Recoverable or potentially destructive local mutation.
        BaselineRestriction::Ask
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    IncompleteTargets,
    UnknownBlastRadius,
    UnknownEffect,
    UnknownEnvironment,
    UnknownReversibility,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::IncompleteTargets => "operation targets were not fully resolved",
            Self::UnknownBlastRadius => "operation blast radius is unknown",
            Self::UnknownEffect => "operation effect is unknown",
            Self::UnknownEnvironment => "operation environment is unknown",
            Self::UnknownReversibility => "operation reversibility is unknown",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProofError {}

/// Everything the platform resolver must establish before an interpreted
/// intent can become evidence.
///
/// No field here is derivable from a command string. Containment needs
/// canonicalization against a trusted boundary; environment comes from trusted
/// configuration and never from an agent label. The resolver is a later
/// Milestone 1 slice, so nothing in the shipped pipeline can supply this yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedContext {
    pub containment: Containment,
    pub target_completeness: TargetCompleteness,
    pub environment: EnvironmentClass,
    pub blast_radius: BlastRadius,
    pub reversibility: Reversibility,
}

/// Builds evidence from an interpreted intent plus resolver-supplied context.
///
/// This is the only sanctioned path from an [`ofw_intent::IntentCandidate`] to
/// [`OperationEvidence`], and it exists so that one property cannot be bypassed
/// by a caller assembling evidence by hand: `execution_surface` is taken from
/// the intent's recorded risk and is **never** `None` for an interpreted
/// command.
///
/// That matters most for git, which reads repository-controlled configuration.
/// `core.fsmonitor`, `core.pager`, `diff.*.textconv` and external diff drivers
/// all name programs git will execute, set in `.git/config` by the repository
/// with no command-line flag involved. `git status` therefore cannot reach the
/// bounded-read allow row, and settles at `ask` rather than `allow`.
#[must_use]
pub fn evidence_from_intent(
    candidate: &ofw_intent::IntentCandidate,
    resolved: &ResolvedContext,
    grammar_revision: Version,
) -> OperationEvidence {
    let execution_surface = match candidate.execution_surface_risk() {
        // The risk enum has no "none" variant by design; this match is the
        // guard that keeps it that way if one is ever added.
        ofw_intent::ExecutionSurfaceRisk::RepositoryConfigControlled => ExecutionSurface::Present,
    };

    OperationEvidence {
        grammar_revision,
        operation_kind: candidate.operation_kind().clone(),
        effect: candidate.effect(),
        execution_surface,
        target_completeness: resolved.target_completeness,
        containment: resolved.containment,
        // Privilege and publication are resolver concerns too. Standard and
        // not-applicable are correct for the read-only subset interpreted
        // today and must be revisited when mutations are interpreted.
        privilege: PrivilegeRequirement::Standard,
        publication: Publication::NotApplicable,
        reversibility: resolved.reversibility,
        blast_radius: resolved.blast_radius,
        environment: resolved.environment,
    }
}

/// Joins the built-in baseline with the policy restriction.
///
/// An absent proof is always `Indeterminate`: the operation was not recognized
/// completely enough to be given any baseline, and unknown is not safe.
///
/// `PolicyOutcome::NoRestriction` contributes `BaselineRestriction::Allow` to
/// the join. That is the *identity element* of `max`, not an authorization:
/// `max(baseline, Allow) == baseline` for every baseline, so policy adding
/// nothing leaves the baseline exactly as the built-in derivation set it. An
/// operation reaches `Allow` only when its own proof derives `Allow`.
#[must_use]
pub fn decide(
    proof: Option<&SupportedOperationProof>,
    evaluation: &PolicyEvaluation,
) -> DecisionOutcome {
    let Some(proof) = proof else {
        return DecisionOutcome::Indeterminate;
    };

    let policy = match evaluation.outcome {
        PolicyOutcome::Indeterminate => return DecisionOutcome::Indeterminate,
        PolicyOutcome::NoRestriction => BaselineRestriction::Allow,
        PolicyOutcome::Ask => BaselineRestriction::Ask,
        PolicyOutcome::Deny => BaselineRestriction::Deny,
    };

    match proof.baseline().max(policy) {
        BaselineRestriction::Allow => DecisionOutcome::Allow,
        BaselineRestriction::Ask => DecisionOutcome::Ask,
        BaselineRestriction::Deny => DecisionOutcome::Deny,
    }
}

#[cfg(test)]
mod tests {
    use ofw_contracts::{
        BlastRadius, EnvironmentClass, Identifier, NamespacedName, OperationEffect, PolicyLayer,
        Restriction, Reversibility, Version,
    };
    use ofw_policy::{
        EffectivePolicy, Fact, OperationFacts, PolicyEvaluation, PolicyOutcome, RestrictionRule,
        Selectors, ValidatedPolicyBundle,
    };
    use std::collections::BTreeSet;

    use super::{
        BaselineRestriction, Containment, DecisionOutcome, ExecutionSurface, OperationEvidence,
        PrivilegeRequirement, ProofError, Publication, ResolvedContext, SupportedOperationProof,
        TargetCompleteness, decide, evidence_from_intent,
    };

    fn name(value: &str) -> NamespacedName {
        match NamespacedName::new(value) {
            Ok(name) => name,
            Err(error) => unreachable!("test name must be valid: {error}"),
        }
    }

    fn version(value: &str) -> Version {
        match Version::new(value) {
            Ok(version) => version,
            Err(error) => unreachable!("test version must be valid: {error}"),
        }
    }

    /// A bounded, non-executing, repository-local read in a local environment:
    /// the clearest allow case in the matrix. Individual tests vary one field.
    fn readable_evidence() -> OperationEvidence {
        OperationEvidence {
            grammar_revision: version("1.0.0"),
            operation_kind: name("git.status"),
            effect: OperationEffect::Read,
            execution_surface: ExecutionSurface::None,
            target_completeness: TargetCompleteness::Complete,
            containment: Containment::RepositoryLocal,
            privilege: PrivilegeRequirement::Standard,
            publication: Publication::NotApplicable,
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Single,
            environment: EnvironmentClass::Local,
        }
    }

    fn proof(evidence: OperationEvidence) -> SupportedOperationProof {
        match SupportedOperationProof::new(evidence) {
            Ok(proof) => proof,
            Err(error) => unreachable!("test evidence must be provable: {error}"),
        }
    }

    /// A policy that restricts nothing for the facts under test.
    fn no_restriction() -> PolicyEvaluation {
        let effective = match EffectivePolicy::compose(Vec::new()) {
            Ok(effective) => effective,
            Err(error) => unreachable!("empty policy must compose: {error:?}"),
        };
        effective.evaluate(&unrelated_facts())
    }

    fn deny_everything() -> PolicyEvaluation {
        let restriction_rule = match RestrictionRule::new(
            match Identifier::new("deny-status") {
                Ok(identifier) => identifier,
                Err(error) => unreachable!("test identifier must be valid: {error}"),
            },
            Restriction::Deny,
            Selectors::for_operation_kind(name("git.status")),
            BTreeSet::from([name("git.history_loss")]),
            "Deny the operation.",
            Vec::new(),
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        };
        let bundle = match ValidatedPolicyBundle::new(
            PolicyLayer::Organization,
            match Identifier::new("org.deny") {
                Ok(identifier) => identifier,
                Err(error) => unreachable!("test identifier must be valid: {error}"),
            },
            version("1.0.0"),
            vec![restriction_rule],
        ) {
            Ok(bundle) => bundle,
            Err(error) => unreachable!("test bundle must be valid: {error:?}"),
        };
        let effective = match EffectivePolicy::compose([bundle]) {
            Ok(effective) => effective,
            Err(error) => unreachable!("test policy must compose: {error:?}"),
        };
        effective.evaluate(&unrelated_facts())
    }

    fn unrelated_facts() -> OperationFacts {
        match OperationFacts::new(
            Fact::Known(name("git.status")),
            Fact::Known(OperationEffect::Read),
            Fact::Known(BTreeSet::from([name("git.repository")])),
            Fact::Known(EnvironmentClass::Local),
            Fact::Known(Reversibility::Reversible),
            Fact::Known(BlastRadius::Single),
        ) {
            Ok(facts) => facts,
            Err(error) => unreachable!("test facts must be valid: {error:?}"),
        }
    }

    #[test]
    fn red_first_witness_detects_no_restriction_mapped_to_allow() {
        // A destructive-but-recoverable local mutation: baseline `Ask`.
        let mutation = OperationEvidence {
            operation_kind: name("filesystem.remove"),
            effect: OperationEffect::Delete,
            reversibility: Reversibility::Recoverable,
            ..readable_evidence()
        };
        let supported = proof(mutation);
        let evaluation = no_restriction();

        assert_eq!(evaluation.outcome, PolicyOutcome::NoRestriction);
        assert_eq!(supported.baseline(), BaselineRestriction::Ask);
        assert_eq!(decide(Some(&supported), &evaluation), DecisionOutcome::Ask);
        // The retained vulnerable form reads "no rule objected" as "permitted"
        // and authorizes an operation the built-in baseline wanted to ask about.
        assert_eq!(
            vulnerable_no_restriction_means_allow(&evaluation),
            DecisionOutcome::Allow
        );
    }

    #[test]
    fn red_first_witness_detects_absent_proof_defaulting_to_allow() {
        let evaluation = no_restriction();

        assert_eq!(decide(None, &evaluation), DecisionOutcome::Indeterminate);
        // The retained vulnerable form authorizes an operation that was never
        // recognized at all.
        assert_eq!(
            vulnerable_absent_proof_allows(None, &evaluation),
            DecisionOutcome::Allow
        );
    }

    #[test]
    fn red_first_witness_detects_policy_overriding_the_baseline() {
        // Permission change: baseline `Deny` on the effect alone.
        let privileged = OperationEvidence {
            operation_kind: name("filesystem.chmod"),
            effect: OperationEffect::PermissionChange,
            ..readable_evidence()
        };
        let supported = proof(privileged);
        let evaluation = no_restriction();

        assert_eq!(supported.baseline(), BaselineRestriction::Deny);
        assert_eq!(decide(Some(&supported), &evaluation), DecisionOutcome::Deny);
        // The retained vulnerable form lets a silent policy erase a built-in
        // deny, which is the "policy can only add restriction" invariant
        // inverted.
        assert_eq!(
            vulnerable_policy_overrides_baseline(Some(&supported), &evaluation),
            DecisionOutcome::Allow
        );
    }

    #[test]
    fn red_first_witness_detects_permissive_derivation_order() {
        // A bounded, non-executing read *of a security control*: it satisfies
        // the read allow row and the privilege deny row simultaneously.
        let security_control_read = OperationEvidence {
            privilege: PrivilegeRequirement::SecurityControl,
            ..readable_evidence()
        };
        let supported = proof(security_control_read.clone());

        assert_eq!(supported.baseline(), BaselineRestriction::Deny);
        // The retained allow-first ordering flips exactly this case.
        assert_eq!(
            vulnerable_allow_first_baseline(&security_control_read),
            BaselineRestriction::Allow
        );
    }

    /// The write allow row must demand the same absent execution surface the
    /// read allow row demands.
    ///
    /// The asymmetry this pins is easy to reintroduce because it reads as
    /// harmless: an edit is already constrained to be reversible and
    /// repository-local, so requiring one more thing looks redundant. It is
    /// not. The execution surface is not a property of the *edit*, it is a
    /// property of the *command performing the edit* -- and a command that
    /// consults repository-controlled configuration can name further programs
    /// to run, whatever it does to the file it names. A write earns less
    /// benefit of the doubt than a read, not more.
    #[test]
    fn red_first_witness_detects_a_write_allow_row_that_ignores_the_execution_surface() {
        let edit_through_an_executing_command = OperationEvidence {
            operation_kind: name("filesystem.write"),
            effect: OperationEffect::Update,
            execution_surface: ExecutionSurface::Present,
            ..readable_evidence()
        };

        // Every other dimension is maximally favourable -- bounded, reversible,
        // repository-local, local environment -- so the execution surface is
        // the only thing standing between this and an allow.
        assert_eq!(
            proof(edit_through_an_executing_command.clone()).baseline(),
            BaselineRestriction::Ask
        );
        // The same edit with no execution surface is still an allow, so the
        // guard narrows exactly one thing and does not disable the row.
        assert_eq!(
            proof(OperationEvidence {
                execution_surface: ExecutionSurface::None,
                ..edit_through_an_executing_command.clone()
            })
            .baseline(),
            BaselineRestriction::Allow
        );
        // The retained vulnerable row is the read row's guard omitted from the
        // write row, which is what this crate shipped until 2026-08-07.
        assert_eq!(
            vulnerable_write_row_ignores_execution_surface(&edit_through_an_executing_command),
            BaselineRestriction::Allow
        );
    }

    #[test]
    fn baseline_restriction_ordering_is_pinned() {
        // `decide` joins with `max`, which follows declaration order.
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        enum InvertedBaseline {
            Deny,
            Ask,
            Allow,
        }

        assert!(BaselineRestriction::Allow < BaselineRestriction::Ask);
        assert!(BaselineRestriction::Ask < BaselineRestriction::Deny);
        assert_eq!(
            BaselineRestriction::Deny.max(BaselineRestriction::Allow),
            BaselineRestriction::Deny
        );
        // The retained inverted witness returns the weaker value from the
        // identical join, at both steps of the lattice.
        assert_eq!(
            InvertedBaseline::Deny.max(InvertedBaseline::Allow),
            InvertedBaseline::Allow
        );
        assert_eq!(
            InvertedBaseline::Deny.max(InvertedBaseline::Ask),
            InvertedBaseline::Ask
        );
    }

    #[test]
    fn policy_restriction_raises_but_never_lowers_the_baseline() {
        let readable = proof(readable_evidence());
        assert_eq!(readable.baseline(), BaselineRestriction::Allow);

        // Policy adding nothing leaves an allow baseline allowed...
        assert_eq!(
            decide(Some(&readable), &no_restriction()),
            DecisionOutcome::Allow
        );
        // ...and policy adding a deny raises it.
        assert_eq!(
            decide(Some(&readable), &deny_everything()),
            DecisionOutcome::Deny
        );
    }

    #[test]
    fn proof_construction_rejects_unproven_evidence() {
        let cases = [
            (
                OperationEvidence {
                    target_completeness: TargetCompleteness::Incomplete,
                    ..readable_evidence()
                },
                ProofError::IncompleteTargets,
            ),
            (
                OperationEvidence {
                    effect: OperationEffect::UnknownMutation,
                    ..readable_evidence()
                },
                ProofError::UnknownEffect,
            ),
            (
                OperationEvidence {
                    reversibility: Reversibility::Unknown,
                    ..readable_evidence()
                },
                ProofError::UnknownReversibility,
            ),
            (
                OperationEvidence {
                    blast_radius: BlastRadius::Unknown,
                    ..readable_evidence()
                },
                ProofError::UnknownBlastRadius,
            ),
            (
                OperationEvidence {
                    environment: EnvironmentClass::Unknown,
                    ..readable_evidence()
                },
                ProofError::UnknownEnvironment,
            ),
        ];

        for (evidence, expected) in cases {
            assert_eq!(SupportedOperationProof::new(evidence), Err(expected));
        }
    }

    /// Behaviour-pinning, not a security invariant: there is no weakened
    /// implementation this could be red against, because the tightening is the
    /// design. Records that `environment` is read by the derivation, so an
    /// otherwise-allowable reversible repository-local edit does not reach
    /// `Allow` in a production or shared environment.
    #[test]
    fn environment_is_read_by_the_baseline() {
        let local_edit = OperationEvidence {
            operation_kind: name("filesystem.write"),
            effect: OperationEffect::Update,
            ..readable_evidence()
        };
        assert_eq!(
            proof(local_edit.clone()).baseline(),
            BaselineRestriction::Allow
        );

        for environment in [
            EnvironmentClass::Production,
            EnvironmentClass::Shared,
            EnvironmentClass::Staging,
        ] {
            let elevated = OperationEvidence {
                environment,
                ..local_edit.clone()
            };
            assert_eq!(proof(elevated).baseline(), BaselineRestriction::Ask);
        }
    }

    /// The most favourable context a resolver could possibly report.
    ///
    /// Used to show that a git read still does not reach allow even when every
    /// other dimension is maximally permissive -- so the result depends on the
    /// execution surface and nothing else.
    const fn most_permissive_context() -> ResolvedContext {
        ResolvedContext {
            containment: Containment::RepositoryLocal,
            target_completeness: TargetCompleteness::Complete,
            environment: EnvironmentClass::Local,
            blast_radius: BlastRadius::Single,
            reversibility: Reversibility::Reversible,
        }
    }

    fn git_status_intent() -> ofw_intent::IntentCandidate {
        match ofw_intent::interpret("git status") {
            Ok(ofw_intent::Classification::Supported(candidate)) => *candidate,
            other => unreachable!("git status must classify, got {other:?}"),
        }
    }

    #[test]
    fn an_interpreted_git_read_settles_at_ask_not_allow() {
        let evidence = evidence_from_intent(
            &git_status_intent(),
            &most_permissive_context(),
            version("1.0.0"),
        );

        assert_eq!(evidence.execution_surface, ExecutionSurface::Present);
        assert_eq!(evidence.effect, OperationEffect::Read);
        // Every other dimension is maximally favourable, and it is still not
        // an allow: git consults repository-controlled configuration that can
        // name programs to execute, so the bounded-read allow row is unproven.
        assert_eq!(proof(evidence).baseline(), BaselineRestriction::Ask);
    }

    #[test]
    fn red_first_witness_detects_assuming_git_is_non_executing() {
        let permissive = most_permissive_context();
        let intent = git_status_intent();

        let real = evidence_from_intent(&intent, &permissive, version("1.0.0"));
        assert_eq!(proof(real).baseline(), BaselineRestriction::Ask);

        // The retained vulnerable conversion treats an interpreted command as
        // carrying no execution surface, which promotes a bounded read to a
        // clean allow it has not earned.
        let vulnerable = vulnerable_assumes_no_execution_surface(&intent, &permissive);
        assert_eq!(proof(vulnerable).baseline(), BaselineRestriction::Allow);
    }

    /// Retained red-first witness: an intent-to-evidence conversion that
    /// assumes an interpreted command reaches no execution surface.
    fn vulnerable_assumes_no_execution_surface(
        candidate: &ofw_intent::IntentCandidate,
        resolved: &ResolvedContext,
    ) -> OperationEvidence {
        OperationEvidence {
            execution_surface: ExecutionSurface::None,
            ..evidence_from_intent(candidate, resolved, version("1.0.0"))
        }
    }

    /// Retained red-first witness: policy silence read as authorization.
    fn vulnerable_no_restriction_means_allow(evaluation: &PolicyEvaluation) -> DecisionOutcome {
        match evaluation.outcome {
            PolicyOutcome::NoRestriction => DecisionOutcome::Allow,
            PolicyOutcome::Ask => DecisionOutcome::Ask,
            PolicyOutcome::Deny => DecisionOutcome::Deny,
            PolicyOutcome::Indeterminate => DecisionOutcome::Indeterminate,
        }
    }

    /// Retained red-first witness: an unrecognized operation defaulting to allow.
    fn vulnerable_absent_proof_allows(
        proof: Option<&SupportedOperationProof>,
        evaluation: &PolicyEvaluation,
    ) -> DecisionOutcome {
        match proof {
            Some(proof) => decide(Some(proof), evaluation),
            None => DecisionOutcome::Allow,
        }
    }

    /// Retained red-first witness: the policy outcome overriding the built-in
    /// baseline instead of joining with it.
    fn vulnerable_policy_overrides_baseline(
        proof: Option<&SupportedOperationProof>,
        evaluation: &PolicyEvaluation,
    ) -> DecisionOutcome {
        let _ = proof;
        vulnerable_no_restriction_means_allow(evaluation)
    }

    /// Retained red-first witness: the write allow row without the execution
    /// surface guard the read allow row carries.
    ///
    /// Reproduced rather than delegated, because the defect was the *absence*
    /// of a condition -- there is nothing to call that still has it.
    fn vulnerable_write_row_ignores_execution_surface(
        evidence: &OperationEvidence,
    ) -> BaselineRestriction {
        let low_consequence_environment = matches!(
            evidence.environment,
            EnvironmentClass::Local | EnvironmentClass::Development | EnvironmentClass::Test
        );
        let bounded = matches!(
            evidence.blast_radius,
            BlastRadius::Single | BlastRadius::Bounded
        );
        if low_consequence_environment
            && bounded
            && matches!(
                evidence.effect,
                OperationEffect::Create | OperationEffect::Update
            )
            && matches!(evidence.reversibility, Reversibility::Reversible)
            && matches!(evidence.containment, Containment::RepositoryLocal)
        {
            return BaselineRestriction::Allow;
        }
        BaselineRestriction::Ask
    }

    /// Retained red-first witness: the baseline derivation with the allow rows
    /// tested before the deny rows.
    fn vulnerable_allow_first_baseline(evidence: &OperationEvidence) -> BaselineRestriction {
        if matches!(evidence.effect, OperationEffect::Read)
            && matches!(evidence.execution_surface, ExecutionSurface::None)
            && matches!(
                evidence.blast_radius,
                BlastRadius::Single | BlastRadius::Bounded
            )
        {
            return BaselineRestriction::Allow;
        }
        if matches!(
            evidence.privilege,
            PrivilegeRequirement::Elevated | PrivilegeRequirement::SecurityControl
        ) {
            return BaselineRestriction::Deny;
        }
        BaselineRestriction::Ask
    }
}
