//! Envelope to decision, with no path that reaches allow by omission.
//!
//! The pipeline runs a Codex envelope through four stages, and stopping at any
//! of them is a denial rather than a weaker decision:
//!
//! 1. the adapter validates the envelope and extracts the tool payload;
//! 2. `ofw-intent` reduces a command to literal words and classifies it, or
//!    refuses;
//! 3. `ofw-resolve` establishes containment, environment, blast radius and
//!    reversibility against explicit trusted configuration;
//! 4. `ofw-core` derives a baseline from that evidence and joins it with the
//!    policy restriction.
//!
//! An operation that clears all four has a [`SupportedOperationProof`]. That is
//! not the same as being allowed: the only operations interpreted today are git
//! reads, and no git invocation can be proven non-executing from its argv, so a
//! proven git read settles at `ask`. `ask` has no Codex wire representation and
//! denies until Milestone 2 binds an approval.

use std::collections::BTreeSet;

use ofw_adapter_codex::{
    AdapterAssessment, AdapterError, EnvelopeErrorCode, ExtractedToolInput,
    INPUT_PROTOCOL_REVISION, ToolInputErrorCode, assess_supported_pre_tool_use,
};
use ofw_audit::Digest;
use ofw_contracts::{Identifier, Version};
use ofw_core::{
    DecisionOutcome, OperationEvidence, SupportedOperationProof, decide, evidence_from_intent,
};
use ofw_intent::Classification;
use ofw_policy::{EffectivePolicy, Fact, OperationFacts, PolicyEvaluation, PolicyOutcome};
use ofw_resolve::{ResolutionError, TrustedConfiguration};

use ofw_audit::{AuditGate, AuditHealth};

use crate::policy::PolicyActivation;

/// A stable, payload-free explanation code.
///
/// Every value is a `&'static str`. Nothing derived from the tool payload can
/// reach a reason string, which is what keeps commands, patch bodies and any
/// secret embedded in them out of stdout, stderr and future audit records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reason {
    pub code: &'static str,
    pub message: &'static str,
}

pub const ENVELOPE_TOO_LARGE: Reason = Reason {
    code: "ENVELOPE_TOO_LARGE",
    message: "hook envelope exceeds the configured byte limit",
};
const ENVELOPE_INVALID: Reason = Reason {
    code: "ENVELOPE_INVALID",
    message: "hook envelope did not match the supported protocol revision",
};
const TOOL_UNSUPPORTED: Reason = Reason {
    code: "TOOL_UNSUPPORTED",
    message: "tool is outside the supported adapter subset",
};
const TOOL_INPUT_INVALID: Reason = Reason {
    code: "TOOL_INPUT_INVALID",
    message: "tool input did not match the supported payload subset",
};
const INTERPRETATION_UNSUPPORTED: Reason = Reason {
    code: "OPERATION_INTERPRETATION_UNSUPPORTED",
    message: "operation is outside the interpreted subset, so it cannot be \
              proven supported",
};
const COMMAND_NOT_LITERAL: Reason = Reason {
    code: "COMMAND_NOT_LITERAL",
    message: "command contains shell constructs that cannot be resolved to \
              literal words without evaluating them",
};
/// The operation was interpreted, but nothing said where it would run.
///
/// Trusted configuration is not defaulted. Falling back to the process working
/// directory would let whatever launched the hook choose the boundary the
/// operation is measured against, and falling back to the envelope's `cwd`
/// would let the agent choose it.
const TRUSTED_CONFIGURATION_MISSING: Reason = Reason {
    code: "TRUSTED_CONFIGURATION_MISSING",
    message: "no trusted working directory, repository boundary and \
              environment were configured",
};
/// The operation was interpreted, and the resolver has no rule for its targets.
const TARGET_RESOLUTION_UNSUPPORTED: Reason = Reason {
    code: "TARGET_RESOLUTION_UNSUPPORTED",
    message: "operation was interpreted, but its targets are outside the \
              resolved subset",
};
/// The resolver had a rule and could not apply it -- an absent directory, a
/// path past a compiled bound, a name that is not UTF-8.
const TARGET_RESOLUTION_INDETERMINATE: Reason = Reason {
    code: "TARGET_RESOLUTION_INDETERMINATE",
    message: "operation targets could not be canonicalized against the \
              configured repository boundary",
};
/// Resolution succeeded and the evidence still did not establish a proof.
const OPERATION_NOT_PROVABLE: Reason = Reason {
    code: "OPERATION_NOT_PROVABLE",
    message: "resolved evidence did not establish a supported-operation proof",
};
/// A mutation that cannot be recorded is not performed.
///
/// Unreachable while the interpreted subset is read-only -- no envelope can
/// carry a mutation this far. The rule is exercised at `ofw_audit::gate`,
/// which is the function that decides it.
const AUDIT_UNAVAILABLE_FOR_MUTATION: Reason = Reason {
    code: "AUDIT_UNAVAILABLE_FOR_MUTATION",
    message: "operation changes state and no audit trail is available to \
              record it",
};

/// The audit sink's health.
///
/// Persistence is not implemented, so there is no sink and the honest value is
/// `unhealthy`. It is reported rather than assumed: an operator reading
/// `audit: unhealthy` knows that a mutation would be refused today, which is
/// the behaviour they would otherwise discover the first time one mattered.
const AUDIT_HEALTH: AuditHealth = AuditHealth::Unhealthy;

/// Proven, and the built-in baseline asks. Milestone 2 resolves an ask inside
/// the hook against a bound approval; until then it denies on the wire.
const APPROVAL_REQUIRED: Reason = Reason {
    code: "APPROVAL_REQUIRED",
    message: "operation was proven and its baseline requires an approval, \
              which is not implemented",
};
const BASELINE_DENIED: Reason = Reason {
    code: "BASELINE_DENIED",
    message: "operation was proven and the built-in safety baseline denies it",
};
/// Denied because a supplied rule said so, rather than by the baseline.
///
/// Attribution matters to whoever has to act on it: "the built-in baseline
/// denies this" and "your organisation's policy denies this" lead to different
/// next steps, and reporting the first for the second sends an operator to
/// read the wrong document.
const POLICY_DENIED: Reason = Reason {
    code: "POLICY_DENIED",
    message: "operation was proven and a supplied policy rule denies it",
};
const OPERATION_PROVEN: Reason = Reason {
    code: "OPERATION_PROVEN",
    message: "operation was proven and no restriction applies",
};
/// A proof exists and policy could not be resolved -- a loaded rule selected
/// on a fact nobody established.
const POLICY_INDETERMINATE: Reason = Reason {
    code: "POLICY_INDETERMINATE",
    message: "policy evaluation needed a fact that was not established",
};

/// Supplied policy was configured and could not be activated.
///
/// These are not decisions. A configured policy that does not load leaves the
/// system unable to say what is restricted, and that is `indeterminate` -- not
/// the unrestricted behaviour of a deployment that configured no policy.
pub const POLICY_ACTIVATION_UNHEALTHY: Reason = Reason {
    code: "POLICY_ACTIVATION_UNHEALTHY",
    message: "configured policy could not be activated, so no decision can be \
              made",
};
pub const POLICY_LOCATION_UNREADABLE: Reason = Reason {
    code: "POLICY_LOCATION_UNREADABLE",
    message: "configured policy location could not be read",
};
pub const POLICY_BUNDLE_INVALID: Reason = Reason {
    code: "POLICY_BUNDLE_INVALID",
    message: "a configured policy bundle did not match the v1 contract",
};
pub const POLICY_TOO_MANY_BUNDLES: Reason = Reason {
    code: "POLICY_TOO_MANY_BUNDLES",
    message: "configured policy location holds more bundles than the compiled \
              maximum",
};

pub const INPUT_READ_FAILED: Reason = Reason {
    code: "INPUT_READ_FAILED",
    message: "hook input could not be read",
};
pub const DEADLINE_EXCEEDED: Reason = Reason {
    code: "DEADLINE_EXCEEDED",
    message: "decision deadline elapsed before a decision was reached",
};
pub const INTERNAL_FAILURE: Reason = Reason {
    code: "INTERNAL_FAILURE",
    message: "decision core failed before reaching a decision",
};
pub const USAGE_INVALID: Reason = Reason {
    code: "USAGE_INVALID",
    message: "hook invocation arguments were not understood",
};

/// One assessed operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assessment {
    pub outcome: DecisionOutcome,
    pub reason: Reason,
    /// Whether the decision was reached with a working audit trail.
    ///
    /// Reported rather than folded into the outcome, because a read that
    /// proceeded on a degraded sink is a different situation from one that
    /// proceeded on a healthy one, and a log that cannot tell them apart
    /// cannot answer "was this recorded?" afterwards.
    pub audit_health: &'static str,
    /// `None` until the envelope has been validated far enough to know it.
    /// Only ever one of the adapter's compiled-in supported tool names.
    pub tool_name: Option<&'static str>,
    /// The normalized operation kind, when interpretation succeeded.
    pub operation_kind: Option<&'static str>,
    pub proof_present: bool,
    pub policy_outcome: &'static str,
    /// Digests of the identities this decision concerned.
    ///
    /// Digests rather than the identities: `session_id` and `turn_id` are
    /// agent-supplied strings, and an audit record that carried them raw would
    /// be carrying attacker-influenced text into a log that is read later by a
    /// human and parsed by tooling.
    pub references: AuditReferences,
}

/// Payload-free references for one assessed operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReferences {
    pub session: Digest,
    pub invocation: Digest,
    /// A bounded identifier derived from the invocation digest. Correlates
    /// records without echoing anything the agent chose.
    pub correlation: Identifier,
}

impl AuditReferences {
    fn derive(input: &[u8], session_id: &str) -> Self {
        let invocation = Digest::of(input);
        // The contract's `id` pattern admits lowercase hex, so a digest prefix
        // is a valid identifier and cannot fail validation.
        let correlation = match Identifier::new(&invocation.value()[..32]) {
            Ok(identifier) => identifier,
            // A hex prefix always validates. If that ever stops being true the
            // record still gets a usable identity rather than the operation
            // failing over a diagnostic field.
            Err(_) => match Identifier::new("unattributed") {
                Ok(identifier) => identifier,
                Err(_) => unreachable!("a compiled-in identifier must validate"),
            },
        };
        Self {
            session: Digest::of(session_id.as_bytes()),
            invocation,
            correlation,
        }
    }

    fn unattributed() -> Self {
        Self::derive(b"", "")
    }

    /// The references for a decision made before any input was read.
    #[must_use]
    pub fn unattributed_public() -> Self {
        Self::unattributed()
    }
}

/// How far one operation got before a decision was reached.
enum Stage {
    /// Stopped before a proof could be built. Always `indeterminate`.
    Blocked {
        reason: Reason,
        operation_kind: Option<&'static str>,
    },
    Proven {
        operation_kind: &'static str,
        proof: Box<SupportedOperationProof>,
    },
}

/// Everything a decision depends on besides the envelope itself.
///
/// Passed in rather than read here, so that no caller can be given a decision
/// that silently depends on ambient process state.
pub struct AssessmentContext<'a> {
    /// `None` means none was configured. An operation that cannot be placed
    /// cannot be proven.
    pub configuration: Option<&'a TrustedConfiguration>,
    pub policy: &'a PolicyActivation,
}

/// Assesses one Codex `PreToolUse` envelope.
#[must_use]
pub fn assess(input: &[u8], context: &AssessmentContext<'_>) -> Assessment {
    // System health is checked before anything is interpreted. A firewall that
    // cannot tell what is restricted has no business deciding, and reporting
    // the health fault first is what tells an operator the actionable thing
    // rather than a downstream symptom of it.
    let policy = match context.policy {
        PolicyActivation::Unhealthy(reason) => {
            return Assessment {
                outcome: DecisionOutcome::Indeterminate,
                reason: *reason,
                audit_health: "unknown",
                tool_name: None,
                operation_kind: None,
                proof_present: false,
                policy_outcome: "unhealthy",
                references: AuditReferences::unattributed(),
            };
        }
        PolicyActivation::Healthy { policy, .. } => policy,
    };

    let extracted = match assess_supported_pre_tool_use(input) {
        AdapterAssessment::Extracted(extracted) => extracted,
        AdapterAssessment::Indeterminate(error) => {
            return blocked(
                policy,
                adapter_reason(&error),
                None,
                None,
                AuditReferences::derive(input, ""),
            );
        }
    };

    // Narrow the borrowed tool name to a compiled-in literal. The adapter has
    // already rejected anything outside this set; re-deriving the literal here
    // means no borrowed input string can reach the output.
    let tool_name = match extracted.envelope().tool_name() {
        "Bash" => Some("Bash"),
        "apply_patch" => Some("apply_patch"),
        _ => None,
    };

    // `extracted.envelope().cwd()` is deliberately not read here or anywhere
    // below. It is the agent's claim about where its command would run, and
    // resolving against it would let the operation choose the boundary it is
    // measured against. `red_first_witness_detects_trusting_the_envelope_cwd`
    // retains a pipeline that does read it.
    let references = AuditReferences::derive(input, extracted.envelope().session_id());

    let stage = match extracted.tool_input() {
        ExtractedToolInput::Bash(bash) => {
            interpret_and_resolve(bash.command(), context.configuration)
        }
        // The apply-patch grammar is a separate slice.
        ExtractedToolInput::ApplyPatch(_) => Stage::Blocked {
            reason: INTERPRETATION_UNSUPPORTED,
            operation_kind: None,
        },
    };

    match stage {
        Stage::Blocked {
            reason,
            operation_kind,
        } => blocked(policy, reason, tool_name, operation_kind, references),
        Stage::Proven {
            operation_kind,
            proof,
        } => {
            let evaluation = evaluate(policy, Some(proof.evidence()));
            let decided = decide(Some(&proof), &evaluation);

            // A decision that cannot be recorded is not automatically a
            // decision. The gate raises a mutation to indeterminate when there
            // is no audit trail, and lets a read through with its health
            // reported honestly.
            let (outcome, reason, audit_health) =
                match ofw_audit::gate(proof.evidence().effect, AUDIT_HEALTH) {
                    AuditGate::Proceed => (
                        decided,
                        decided_reason(decided, evaluation.outcome),
                        "healthy",
                    ),
                    AuditGate::ProceedDegraded => (
                        decided,
                        decided_reason(decided, evaluation.outcome),
                        "degraded",
                    ),
                    AuditGate::Indeterminate => (
                        DecisionOutcome::Indeterminate,
                        AUDIT_UNAVAILABLE_FOR_MUTATION,
                        "unhealthy",
                    ),
                };

            Assessment {
                outcome,
                reason,
                audit_health,
                tool_name,
                operation_kind: Some(operation_kind),
                proof_present: true,
                policy_outcome: policy_outcome_name(&evaluation),
                references,
            }
        }
    }
}

/// Interprets one Bash command and resolves its targets.
///
/// The returned operation kind is narrowed to a compiled-in literal rather
/// than borrowed from the interpreter's output, so no payload-derived string
/// can reach stdout, stderr or a future audit record.
fn interpret_and_resolve(command: &str, configuration: Option<&TrustedConfiguration>) -> Stage {
    let candidate = match ofw_intent::interpret(command) {
        Err(_) => return blocked_stage(COMMAND_NOT_LITERAL, None),
        Ok(Classification::Unsupported(_)) => {
            return blocked_stage(INTERPRETATION_UNSUPPORTED, None);
        }
        Ok(Classification::Supported(candidate)) => candidate,
    };

    let operation_kind = match candidate.operation_kind().as_str() {
        "git.status" => "git.status",
        "git.rev_parse" => "git.rev_parse",
        // Interpreted by a grammar this function has no literal for. Reporting
        // it as uninterpreted is the safe direction of the two.
        _ => return blocked_stage(INTERPRETATION_UNSUPPORTED, None),
    };

    let Some(configuration) = configuration else {
        return blocked_stage(TRUSTED_CONFIGURATION_MISSING, Some(operation_kind));
    };

    let resolved = match ofw_resolve::resolve(&candidate, configuration) {
        Ok(resolved) => resolved,
        Err(error) => return blocked_stage(resolution_reason(error), Some(operation_kind)),
    };

    let grammar_revision = match Version::new(ofw_intent::GRAMMAR_REVISION) {
        Ok(version) => version,
        Err(_) => return blocked_stage(INTERNAL_FAILURE, Some(operation_kind)),
    };

    let evidence = evidence_from_intent(&candidate, resolved.context(), grammar_revision);
    match SupportedOperationProof::new(evidence) {
        Ok(proof) => Stage::Proven {
            operation_kind,
            proof: Box::new(proof),
        },
        Err(_) => blocked_stage(OPERATION_NOT_PROVABLE, Some(operation_kind)),
    }
}

const fn blocked_stage(reason: Reason, operation_kind: Option<&'static str>) -> Stage {
    Stage::Blocked {
        reason,
        operation_kind,
    }
}

const fn resolution_reason(error: ResolutionError) -> Reason {
    match error {
        // No rule for these targets yet.
        ResolutionError::OperationKindUnsupported
        | ResolutionError::PathTargetsUnsupported
        | ResolutionError::EffectUnsupported => TARGET_RESOLUTION_UNSUPPORTED,
        // A rule that could not be applied to this filesystem.
        ResolutionError::RepositoryBoundaryUnresolvable
        | ResolutionError::WorkingDirectoryUnresolvable
        | ResolutionError::NonUtf8Path
        | ResolutionError::PathTooLong
        | ResolutionError::TooManyPathSegments
        | ResolutionError::TargetKindUnrepresentable => TARGET_RESOLUTION_INDETERMINATE,
    }
}

/// The reason attached to a decision that was actually reached.
///
/// A deny is attributed to whichever layer produced it. The join takes the
/// most restrictive of the two, so a policy deny is the cause exactly when
/// policy said deny -- and when both did, naming policy is still correct,
/// because removing the policy rule would not lift the decision either way.
const fn decided_reason(outcome: DecisionOutcome, policy: PolicyOutcome) -> Reason {
    match outcome {
        DecisionOutcome::Allow => OPERATION_PROVEN,
        DecisionOutcome::Ask => APPROVAL_REQUIRED,
        DecisionOutcome::Deny => match policy {
            PolicyOutcome::Deny => POLICY_DENIED,
            PolicyOutcome::NoRestriction | PolicyOutcome::Ask | PolicyOutcome::Indeterminate => {
                BASELINE_DENIED
            }
        },
        DecisionOutcome::Indeterminate => POLICY_INDETERMINATE,
    }
}

fn blocked(
    policy: &EffectivePolicy,
    reason: Reason,
    tool_name: Option<&'static str>,
    operation_kind: Option<&'static str>,
    references: AuditReferences,
) -> Assessment {
    let evaluation = evaluate(policy, None);
    Assessment {
        // No proof, so `decide` is `Indeterminate` whatever policy said. Going
        // through `decide` rather than writing the variant here keeps the one
        // rule that produces it in one place.
        outcome: decide(None, &evaluation),
        reason,
        // Nothing was decided, so nothing needed recording.
        audit_health: "not_applicable",
        tool_name,
        operation_kind,
        proof_present: false,
        policy_outcome: policy_outcome_name(&evaluation),
        references,
    }
}

/// Evaluates the activated policy against what is actually established.
///
/// The facts are built from resolver-established evidence rather than from the
/// command. An operation with no proof supplies no facts at all -- an
/// unresolved operation has not established anything, and a rule that needed
/// one of those facts must come out indeterminate rather than quietly not
/// matching.
fn evaluate(effective: &EffectivePolicy, evidence: Option<&OperationEvidence>) -> PolicyEvaluation {
    let facts = match evidence {
        None => OperationFacts::new(
            Fact::Unknown,
            Fact::Unknown,
            Fact::Unknown,
            Fact::Unknown,
            Fact::Unknown,
            Fact::Unknown,
        ),
        Some(evidence) => OperationFacts::new(
            Fact::Known(evidence.operation_kind.clone()),
            Fact::Known(evidence.effect),
            // Target kinds are resolver output, and the resolver's are not
            // threaded here yet. `Unknown` makes a rule that selects on one
            // indeterminate, which denies -- the safe direction.
            Fact::Unknown,
            Fact::Known(evidence.environment),
            Fact::Known(evidence.reversibility),
            Fact::Known(evidence.blast_radius),
        ),
    };

    match facts {
        Ok(facts) => effective.evaluate(&facts),
        Err(_) => indeterminate_evaluation(),
    }
}

fn indeterminate_evaluation() -> PolicyEvaluation {
    PolicyEvaluation {
        outcome: ofw_policy::PolicyOutcome::Indeterminate,
        determining_rules: Vec::new(),
        indeterminate_rules: Vec::new(),
        missing_facts: BTreeSet::new(),
    }
}

fn policy_outcome_name(evaluation: &PolicyEvaluation) -> &'static str {
    match evaluation.outcome {
        ofw_policy::PolicyOutcome::NoRestriction => "no_restriction",
        ofw_policy::PolicyOutcome::Ask => "ask",
        ofw_policy::PolicyOutcome::Deny => "deny",
        ofw_policy::PolicyOutcome::Indeterminate => "indeterminate",
    }
}

fn adapter_reason(error: &AdapterError) -> Reason {
    match error {
        AdapterError::Envelope(envelope) => match envelope.code() {
            EnvelopeErrorCode::InputTooLarge => ENVELOPE_TOO_LARGE,
            EnvelopeErrorCode::UnsupportedTool => TOOL_UNSUPPORTED,
            _ => ENVELOPE_INVALID,
        },
        AdapterError::ToolInput(tool_input) => match tool_input.code() {
            ToolInputErrorCode::UnsupportedTool => TOOL_UNSUPPORTED,
            _ => TOOL_INPUT_INVALID,
        },
    }
}

#[must_use]
pub fn outcome_name(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "allow",
        DecisionOutcome::Ask => "ask",
        DecisionOutcome::Deny => "deny",
        DecisionOutcome::Indeterminate => "indeterminate",
    }
}

#[must_use]
pub const fn protocol_revision() -> &'static str {
    INPUT_PROTOCOL_REVISION
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ofw_contracts::EnvironmentClass;
    use ofw_core::DecisionOutcome;
    use ofw_resolve::TrustedConfiguration;

    use super::{
        APPROVAL_REQUIRED, Assessment, AssessmentContext, BASELINE_DENIED, COMMAND_NOT_LITERAL,
        INTERPRETATION_UNSUPPORTED, POLICY_BUNDLE_INVALID, PolicyActivation, TOOL_UNSUPPORTED,
        TRUSTED_CONFIGURATION_MISSING, assess, outcome_name,
    };

    fn directory(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ofw-pipeline-{}-{label}", std::process::id()));
        match std::fs::create_dir_all(&path) {
            Ok(()) => path,
            Err(error) => unreachable!("test directory must be creatable: {error}"),
        }
    }

    fn configuration(working: PathBuf, boundary: PathBuf) -> TrustedConfiguration {
        match TrustedConfiguration::new(working, boundary, EnvironmentClass::Local) {
            Ok(configuration) => configuration,
            Err(error) => unreachable!("test configuration must be valid: {error:?}"),
        }
    }

    /// A configuration whose working directory is inside its boundary.
    fn contained() -> TrustedConfiguration {
        let boundary = directory("contained");
        configuration(directory("contained/worktree"), boundary)
    }

    fn envelope(command: &str, cwd: &str) -> String {
        format!(
            concat!(
                r#"{{"session_id":"s","transcript_path":null,"cwd":"{}","#,
                r#""hook_event_name":"PreToolUse","model":"m","turn_id":"t","#,
                r#""permission_mode":"default","tool_name":"Bash","tool_use_id":"u","#,
                r#""tool_input":{{"command":"{}"}}}}"#
            ),
            cwd, command
        )
    }

    fn bash(command: &str) -> String {
        envelope(command, "c")
    }

    /// A healthy activation with no supplied policy: restricts nothing, which
    /// is what "no external policy configured" must mean.
    fn healthy_policy() -> PolicyActivation {
        PolicyActivation::none_configured()
    }

    fn assess_str(input: &str, configuration: Option<&TrustedConfiguration>) -> Assessment {
        assess_with(input, configuration, &healthy_policy())
    }

    fn assess_with(
        input: &str,
        configuration: Option<&TrustedConfiguration>,
        policy: &PolicyActivation,
    ) -> Assessment {
        assess(
            input.as_bytes(),
            &AssessmentContext {
                configuration,
                policy,
            },
        )
    }

    #[test]
    fn the_reason_records_which_stage_the_pipeline_reached() {
        let configured = contained();
        // Interpreted and resolved: a decision, not a blockage.
        assert_eq!(
            assess_str(&bash("git status"), Some(&configured)).reason,
            APPROVAL_REQUIRED
        );
        // Interpreted, with nothing to resolve against.
        assert_eq!(
            assess_str(&bash("git status"), None).reason,
            TRUSTED_CONFIGURATION_MISSING
        );
        // Literal words, but outside the interpreted subset.
        assert_eq!(
            assess_str(&bash("git push --force"), Some(&configured)).reason,
            INTERPRETATION_UNSUPPORTED
        );
        // Not reducible to literal words at all -- refused, never partially
        // parsed into a harmless-looking `git status`.
        assert_eq!(
            assess_str(&bash("git status; rm -rf /"), Some(&configured)).reason,
            COMMAND_NOT_LITERAL
        );
    }

    #[test]
    fn a_resolved_repository_read_is_proven_and_asks() {
        let assessment = assess_str(&bash("git status"), Some(&contained()));

        assert!(assessment.proof_present);
        assert_eq!(assessment.outcome, DecisionOutcome::Ask);
        assert_eq!(assessment.operation_kind, Some("git.status"));
        assert_eq!(assessment.tool_name, Some("Bash"));
        // Proven is not allowed. No git invocation can be shown to reach no
        // execution surface from its arguments alone.
        assert_ne!(assessment.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn an_unresolvable_operation_is_indeterminate_rather_than_asked() {
        let assessment = assess_str(&bash("git status"), None);
        assert_eq!(assessment.outcome, DecisionOutcome::Indeterminate);
        assert!(!assessment.proof_present);
    }

    #[test]
    fn policy_silence_does_not_become_allow() {
        // The end-to-end shape of the built-in baseline invariant: policy
        // restricts nothing, and the decision is still not an allow -- both
        // when nothing is proven and when something is.
        for configuration in [None, Some(&contained())] {
            let assessment = assess_str(&bash("git status"), configuration);
            assert_eq!(assessment.policy_outcome, "no_restriction");
            assert_ne!(assessment.outcome, DecisionOutcome::Allow);
        }
    }

    /// A configured policy that cannot be activated is not an unrestricted
    /// one.
    ///
    /// The operation here is fully provable -- interpretation and resolution
    /// both succeed -- so the only thing standing between it and a decision is
    /// that the firewall cannot say what is restricted.
    #[test]
    fn red_first_witness_detects_unloadable_policy_treated_as_empty() {
        let unhealthy = PolicyActivation::Unhealthy(POLICY_BUNDLE_INVALID);
        let configured = contained();

        let real = assess_with(&bash("git status"), Some(&configured), &unhealthy);
        assert_eq!(real.outcome, DecisionOutcome::Indeterminate);
        assert_eq!(real.reason, POLICY_BUNDLE_INVALID);
        assert_eq!(real.policy_outcome, "unhealthy");

        // The retained witness substitutes the empty policy for the one that
        // would not load. The operation becomes an ordinary approvable ask,
        // and any deny the bundle carried is simply not applied.
        let vulnerable = vulnerable_unloadable_policy_is_empty(&bash("git status"), &configured);
        assert_eq!(vulnerable.outcome, DecisionOutcome::Ask);
        assert_eq!(vulnerable.policy_outcome, "no_restriction");
    }

    /// Retained red-first witness: a failed policy activation falling back to
    /// "no policy".
    fn vulnerable_unloadable_policy_is_empty(
        input: &str,
        configuration: &TrustedConfiguration,
    ) -> Assessment {
        let unhealthy = PolicyActivation::Unhealthy(POLICY_BUNDLE_INVALID);
        let substituted = match unhealthy {
            PolicyActivation::Unhealthy(_) => healthy_policy(),
            healthy @ PolicyActivation::Healthy { .. } => healthy,
        };
        assess_with(input, Some(configuration), &substituted)
    }

    /// The agent's claim about where its command runs is not read.
    ///
    /// The trusted working directory here is outside the trusted boundary, so
    /// the real pipeline resolves the operation as cross-boundary and the
    /// baseline denies. The envelope names a `cwd` inside the boundary.
    #[test]
    fn red_first_witness_detects_trusting_the_envelope_cwd() {
        let boundary = directory("cwd-boundary");
        let outside = directory("cwd-outside");
        let claimed = directory("cwd-boundary/claimed");
        let claimed_text = match claimed.to_str() {
            Some(text) => text.replace('\\', "/"),
            None => unreachable!("test path must be UTF-8"),
        };
        let configured = configuration(outside, boundary.clone());
        let input = envelope("git status", &claimed_text);

        let real = assess_str(&input, Some(&configured));
        assert_eq!(real.outcome, DecisionOutcome::Deny);
        assert_eq!(real.reason, BASELINE_DENIED);

        // The retained witness resolves against the envelope's `cwd` instead,
        // and the agent's own claim downgrades its operation from a denial to
        // an approvable ask.
        let vulnerable = vulnerable_trusts_the_envelope_cwd(&input, &configured);
        assert_eq!(vulnerable.outcome, DecisionOutcome::Ask);
    }

    /// Retained red-first witness: a pipeline that resolves relative to the
    /// working directory the envelope claims.
    fn vulnerable_trusts_the_envelope_cwd(
        input: &str,
        configured: &TrustedConfiguration,
    ) -> Assessment {
        let claimed = match ofw_adapter_codex::assess_supported_pre_tool_use(input.as_bytes()) {
            ofw_adapter_codex::AdapterAssessment::Extracted(extracted) => {
                PathBuf::from(extracted.envelope().cwd())
            }
            ofw_adapter_codex::AdapterAssessment::Indeterminate(error) => {
                unreachable!("witness envelope must parse: {error:?}")
            }
        };
        let substituted = configuration(claimed, configured.repository_boundary().to_path_buf());
        assess_str(input, Some(&substituted))
    }

    #[test]
    fn malformed_and_unsupported_inputs_are_indeterminate() {
        let configured = contained();
        for input in [
            "",
            "{",
            "null",
            r#"{"session_id":"s"}"#,
            concat!(
                r#"{"session_id":"s","transcript_path":null,"cwd":"c","#,
                r#""hook_event_name":"PreToolUse","model":"m","turn_id":"t","#,
                r#""permission_mode":"default","tool_name":"WebSearch","#,
                r#""tool_use_id":"u","tool_input":{"command":"x"}}"#
            ),
        ] {
            assert_eq!(
                assess_str(input, Some(&configured)).outcome,
                DecisionOutcome::Indeterminate,
                "input must not be allowed: {input}"
            );
        }
    }

    #[test]
    fn an_unsupported_tool_is_named_as_such() {
        let unsupported = concat!(
            r#"{"session_id":"s","transcript_path":null,"cwd":"c","#,
            r#""hook_event_name":"PreToolUse","model":"m","turn_id":"t","#,
            r#""permission_mode":"default","tool_name":"WebSearch","#,
            r#""tool_use_id":"u","tool_input":{"command":"x"}}"#
        );
        assert_eq!(
            assess_str(unsupported, Some(&contained())).reason,
            TOOL_UNSUPPORTED
        );
    }

    /// Both interpreted kinds reach a proof, not just the one the other tests
    /// use.
    ///
    /// `TARGET_RESOLUTION_UNSUPPORTED` is currently unreachable from here:
    /// this function narrows to `git.status` and `git.rev_parse` before
    /// calling the resolver, both have a declared target scope, both carry
    /// zero operands and both are reads. It is retained as the mapping that
    /// must exist the moment the narrowing list and the resolver's scope list
    /// stop agreeing -- but no test can exercise it, and asserting that some
    /// other reason came back would not be exercising it either.
    #[test]
    fn both_interpreted_kinds_reach_a_proof() {
        for command in ["git status", "git rev-parse --show-toplevel"] {
            let assessment = assess_str(&bash(command), Some(&contained()));
            assert!(assessment.proof_present, "{command} must be provable");
            assert_eq!(assessment.outcome, DecisionOutcome::Ask);
        }
    }

    #[test]
    fn outcome_names_are_stable() {
        assert_eq!(outcome_name(DecisionOutcome::Allow), "allow");
        assert_eq!(outcome_name(DecisionOutcome::Ask), "ask");
        assert_eq!(outcome_name(DecisionOutcome::Deny), "deny");
        assert_eq!(
            outcome_name(DecisionOutcome::Indeterminate),
            "indeterminate"
        );
    }
}
