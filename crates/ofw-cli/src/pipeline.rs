//! Envelope to decision, with no path that reaches allow by omission.
//!
//! The pipeline is deliberately short today: a Codex envelope is validated,
//! its payload is extracted, and then it stops. Turning an extracted Bash
//! command or patch into an `OperationIntent` needs the closed shell, Git and
//! apply-patch grammars, which are a separate Milestone 1 slice. Until those
//! land, no [`SupportedOperationProof`] can be built for any real operation,
//! so every operation is `Indeterminate`, and the Codex hook denies.
//!
//! That is the intended behaviour, not a placeholder: an operation the system
//! cannot interpret is exactly the case that must not be allowed.

use ofw_adapter_codex::{
    AdapterAssessment, AdapterError, EnvelopeErrorCode, ExtractedToolInput,
    INPUT_PROTOCOL_REVISION, ToolInputErrorCode, assess_supported_pre_tool_use,
};
use ofw_core::{DecisionOutcome, SupportedOperationProof, decide};
use ofw_intent::Classification;
use ofw_policy::{EffectivePolicy, Fact, OperationFacts};

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
/// The operation *was* interpreted. It still cannot be proven, because
/// containment and target completeness are resolver facts and the platform
/// resolver is a later slice. This is one stage further than
/// `OPERATION_INTERPRETATION_UNSUPPORTED`, and the distinction is asserted.
const TARGET_RESOLUTION_UNSUPPORTED: Reason = Reason {
    code: "TARGET_RESOLUTION_UNSUPPORTED",
    message: "operation was interpreted, but target resolution is not \
              implemented, so no supported-operation proof can be built",
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

/// Assesses one Codex `PreToolUse` envelope.
#[must_use]
pub fn assess(input: &[u8]) -> Assessment {
    let extracted = match assess_supported_pre_tool_use(input) {
        AdapterAssessment::Extracted(extracted) => extracted,
        AdapterAssessment::Indeterminate(error) => {
            return indeterminate(adapter_reason(&error), None);
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

    let (reason, operation_kind) = match extracted.tool_input() {
        ExtractedToolInput::Bash(bash) => interpret_command(bash.command()),
        // The apply-patch grammar is a separate slice.
        ExtractedToolInput::ApplyPatch(_) => (INTERPRETATION_UNSUPPORTED, None),
    };

    // Even a fully interpreted operation yields no proof: `evidence_from_intent`
    // requires resolver-supplied containment and target completeness, and no
    // resolver exists. `decide` returns `Indeterminate` for an absent proof
    // regardless of what policy says -- the property worth showing end to end.
    let proof: Option<&SupportedOperationProof> = None;
    let evaluation = empty_policy_evaluation();
    let outcome = decide(proof, &evaluation);

    Assessment {
        outcome,
        reason,
        tool_name,
        operation_kind,
        proof_present: false,
        policy_outcome: policy_outcome_name(&evaluation),
    }
}

/// Interprets one Bash command, returning how far the pipeline got.
///
/// The returned operation kind is narrowed to a compiled-in literal rather
/// than borrowed from the interpreter's output, so no payload-derived string
/// can reach stdout, stderr or a future audit record.
fn interpret_command(command: &str) -> (Reason, Option<&'static str>) {
    match ofw_intent::interpret(command) {
        Err(_) => (COMMAND_NOT_LITERAL, None),
        Ok(Classification::Unsupported(_)) => (INTERPRETATION_UNSUPPORTED, None),
        Ok(Classification::Supported(candidate)) => {
            let kind = match candidate.operation_kind().as_str() {
                "git.status" => Some("git.status"),
                "git.rev_parse" => Some("git.rev_parse"),
                _ => None,
            };
            (TARGET_RESOLUTION_UNSUPPORTED, kind)
        }
    }
}

fn indeterminate(reason: Reason, tool_name: Option<&'static str>) -> Assessment {
    let evaluation = empty_policy_evaluation();
    Assessment {
        outcome: DecisionOutcome::Indeterminate,
        reason,
        tool_name,
        operation_kind: None,
        proof_present: false,
        policy_outcome: policy_outcome_name(&evaluation),
    }
}

/// An empty effective policy evaluated against wholly unknown facts.
///
/// No policy bundle loader exists yet. An empty policy restricts nothing, so
/// this evaluates to `NoRestriction` -- and the assessment still comes out
/// `Indeterminate`, because no proof supports it. That pairing is the whole
/// point of the built-in baseline and is asserted end to end.
fn empty_policy_evaluation() -> ofw_policy::PolicyEvaluation {
    let effective = match EffectivePolicy::compose(Vec::new()) {
        Ok(effective) => effective,
        // Composing zero bundles cannot fail; treat any future change that
        // makes it fallible as a denial rather than a panic.
        Err(_) => return unrestricted_fallback(),
    };
    let facts = match OperationFacts::new(
        Fact::Unknown,
        Fact::Unknown,
        Fact::Unknown,
        Fact::Unknown,
        Fact::Unknown,
        Fact::Unknown,
    ) {
        Ok(facts) => facts,
        Err(_) => return unrestricted_fallback(),
    };
    effective.evaluate(&facts)
}

fn unrestricted_fallback() -> ofw_policy::PolicyEvaluation {
    ofw_policy::PolicyEvaluation {
        outcome: ofw_policy::PolicyOutcome::Indeterminate,
        determining_rules: Vec::new(),
        indeterminate_rules: Vec::new(),
        missing_facts: std::collections::BTreeSet::new(),
    }
}

fn policy_outcome_name(evaluation: &ofw_policy::PolicyEvaluation) -> &'static str {
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
    use super::{
        Assessment, COMMAND_NOT_LITERAL, INTERPRETATION_UNSUPPORTED, TARGET_RESOLUTION_UNSUPPORTED,
        TOOL_UNSUPPORTED, assess, empty_policy_evaluation, outcome_name,
    };
    use ofw_core::DecisionOutcome;

    const VALID_BASH: &str = concat!(
        r#"{"session_id":"session-1","transcript_path":null,"cwd":"F:/repo","#,
        r#""hook_event_name":"PreToolUse","model":"gpt-5","turn_id":"turn-1","#,
        r#""permission_mode":"default","tool_name":"Bash","tool_use_id":"tool-1","#,
        r#""tool_input":{"command":"git status"}}"#
    );

    fn assess_str(input: &str) -> Assessment {
        assess(input.as_bytes())
    }

    fn bash(command: &str) -> String {
        format!(
            concat!(
                r#"{{"session_id":"s","transcript_path":null,"cwd":"c","#,
                r#""hook_event_name":"PreToolUse","model":"m","turn_id":"t","#,
                r#""permission_mode":"default","tool_name":"Bash","tool_use_id":"u","#,
                r#""tool_input":{{"command":"{}"}}}}"#
            ),
            command
        )
    }

    #[test]
    fn the_reason_records_which_stage_the_pipeline_reached() {
        // Interpreted, blocked one stage later at resolution.
        assert_eq!(assess_str(VALID_BASH).reason, TARGET_RESOLUTION_UNSUPPORTED);
        // Literal words, but outside the interpreted subset.
        assert_eq!(
            assess_str(&bash("git push --force")).reason,
            INTERPRETATION_UNSUPPORTED
        );
        // Not reducible to literal words at all -- refused, never partially
        // parsed into a harmless-looking `git status`.
        assert_eq!(
            assess_str(&bash("git status; rm -rf /")).reason,
            COMMAND_NOT_LITERAL
        );
    }

    #[test]
    fn a_valid_envelope_is_indeterminate_because_nothing_can_be_proven() {
        let assessment = assess_str(VALID_BASH);
        assert_eq!(assessment.outcome, DecisionOutcome::Indeterminate);
        assert_eq!(assessment.reason, TARGET_RESOLUTION_UNSUPPORTED);
        assert_eq!(assessment.operation_kind, Some("git.status"));
        assert_eq!(assessment.tool_name, Some("Bash"));
        assert!(!assessment.proof_present);
    }

    #[test]
    fn policy_silence_does_not_become_allow() {
        // The end-to-end shape of the built-in baseline invariant: policy
        // restricts nothing, and the decision is still not an allow.
        let assessment = assess_str(VALID_BASH);
        assert_eq!(assessment.policy_outcome, "no_restriction");
        assert_ne!(assessment.outcome, DecisionOutcome::Allow);
        assert_eq!(
            empty_policy_evaluation().outcome,
            ofw_policy::PolicyOutcome::NoRestriction
        );
    }

    #[test]
    fn malformed_and_unsupported_inputs_are_indeterminate() {
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
                assess_str(input).outcome,
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
        assert_eq!(assess_str(unsupported).reason, TOOL_UNSUPPORTED);
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
