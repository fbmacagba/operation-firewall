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
use ofw_contracts::Version;
use ofw_core::{
    DecisionOutcome, OperationEvidence, SupportedOperationProof, decide, evidence_from_intent,
};
use ofw_intent::Classification;
use ofw_policy::{EffectivePolicy, Fact, OperationFacts, PolicyEvaluation};
use ofw_resolve::{ResolutionError, TrustedConfiguration};

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
const OPERATION_PROVEN: Reason = Reason {
    code: "OPERATION_PROVEN",
    message: "operation was proven and no restriction applies",
};
/// A proof exists and policy could not be resolved. Unreachable while no
/// policy bundle loader exists; kept because it is the outcome a rule
/// selecting on a fact nobody established must produce.
const POLICY_INDETERMINATE: Reason = Reason {
    code: "POLICY_INDETERMINATE",
    message: "policy evaluation needed a fact that was not established",
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
    /// `None` until the envelope has been validated far enough to know it.
    /// Only ever one of the adapter's compiled-in supported tool names.
    pub tool_name: Option<&'static str>,
    /// The normalized operation kind, when interpretation succeeded.
    pub operation_kind: Option<&'static str>,
    pub proof_present: bool,
    pub policy_outcome: &'static str,
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

/// Assesses one Codex `PreToolUse` envelope.
///
/// The configuration is a parameter rather than something this function reads,
/// so that no caller can be given a decision that silently depends on ambient
/// process state. `None` means none was configured, and an operation that
/// cannot be placed cannot be proven.
#[must_use]
pub fn assess(input: &[u8], configuration: Option<&TrustedConfiguration>) -> Assessment {
    let extracted = match assess_supported_pre_tool_use(input) {
        AdapterAssessment::Extracted(extracted) => extracted,
        AdapterAssessment::Indeterminate(error) => {
            return blocked(adapter_reason(&error), None, None);
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
    let stage = match extracted.tool_input() {
        ExtractedToolInput::Bash(bash) => interpret_and_resolve(bash.command(), configuration),
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
        } => blocked(reason, tool_name, operation_kind),
        Stage::Proven {
            operation_kind,
            proof,
        } => {
            let evaluation = policy_evaluation(Some(proof.evidence()));
            let outcome = decide(Some(&proof), &evaluation);
            Assessment {
                outcome,
                reason: decided_reason(outcome),
                tool_name,
                operation_kind: Some(operation_kind),
                proof_present: true,
                policy_outcome: policy_outcome_name(&evaluation),
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
const fn decided_reason(outcome: DecisionOutcome) -> Reason {
    match outcome {
        DecisionOutcome::Allow => OPERATION_PROVEN,
        DecisionOutcome::Ask => APPROVAL_REQUIRED,
        DecisionOutcome::Deny => BASELINE_DENIED,
        DecisionOutcome::Indeterminate => POLICY_INDETERMINATE,
    }
}

fn blocked(
    reason: Reason,
    tool_name: Option<&'static str>,
    operation_kind: Option<&'static str>,
) -> Assessment {
    let evaluation = policy_evaluation(None);
    Assessment {
        // No proof, so `decide` is `Indeterminate` whatever policy said. Going
        // through `decide` rather than writing the variant here keeps the one
        // rule that produces it in one place.
        outcome: decide(None, &evaluation),
        reason,
        tool_name,
        operation_kind,
        proof_present: false,
        policy_outcome: policy_outcome_name(&evaluation),
    }
}

/// Evaluates the effective policy against what is actually established.
///
/// No policy bundle loader exists yet, so the effective policy is empty and
/// restricts nothing. The facts still matter: they are what a loaded rule
/// would select on, and they are built from resolver-established evidence
/// rather than from the command. An operation with no proof supplies no facts
/// at all -- an unresolved operation has not established anything, and a rule
/// that needed one of those facts must come out indeterminate rather than
/// quietly not matching.
fn policy_evaluation(evidence: Option<&OperationEvidence>) -> PolicyEvaluation {
    let effective = match EffectivePolicy::compose(Vec::new()) {
        Ok(effective) => effective,
        // Composing zero bundles cannot fail; treat any future change that
        // makes it fallible as indeterminate rather than a panic.
        Err(_) => return indeterminate_evaluation(),
    };

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
        APPROVAL_REQUIRED, Assessment, BASELINE_DENIED, COMMAND_NOT_LITERAL,
        INTERPRETATION_UNSUPPORTED, TOOL_UNSUPPORTED, TRUSTED_CONFIGURATION_MISSING, assess,
        outcome_name, policy_evaluation,
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

    fn assess_str(input: &str, configuration: Option<&TrustedConfiguration>) -> Assessment {
        assess(input.as_bytes(), configuration)
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
        assert_eq!(
            policy_evaluation(None).outcome,
            ofw_policy::PolicyOutcome::NoRestriction
        );
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
