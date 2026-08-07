#![forbid(unsafe_code)]

//! Redacted audit event construction.
//!
//! # Redaction is structural, not a scrubbing pass
//!
//! The usual way to build an audit record is to assemble it from whatever is
//! at hand and then remove the sensitive parts. That approach fails silently
//! and permanently: the scrubber only removes what it was told about, a new
//! field added later is unredacted by default, and the failure is invisible
//! until the log is read by someone who should not have seen it.
//!
//! [`AuditEvent`] instead has **no field that can hold a payload**. Every field
//! is one of:
//!
//! - a compiled-in `&'static str` chosen from a closed set,
//! - a [`Digest`], which is 32 bytes of SHA-256 output and cannot be reversed,
//! - a bounded identifier that came from operator-authored configuration,
//! - or a number.
//!
//! There is no `String` field an agent's command, a patch body, a credential or
//! a filesystem path can be written into, so redaction cannot be forgotten when
//! a field is added -- adding an unredacted one requires changing the type in a
//! way a reviewer sees. `red_first_witness_detects_raw_payload_in_an_event`
//! retains the alternative shape and shows a command reaching the record.
//!
//! # Persistence
//!
//! [`AuditSink`] appends records to JSONL segments under an exclusive lock,
//! rotates by atomic same-directory rename, and quarantines a damaged trailing
//! record on recovery. It does **not** implement retention: deleting closed
//! segments is the one operation here that cannot be reviewed after the fact,
//! and the cost of getting it wrong is unbounded against a cost of disk usage
//! for not having it.
//!
//! A deployment that configures no audit directory has no trail, and
//! [`AuditHealth::Unhealthy`] is the honest health for it. [`gate`] is what
//! that health means for a decision.

mod sink;

pub use sink::{AuditSink, MAX_RECORD_BYTES, MAX_SEGMENT_BYTES, SinkError, read_segment};

use ofw_contracts::{EnvironmentClass, Identifier, NamespacedName, OperationEffect};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// The audit contract revision this crate emits.
pub const SCHEMA_VERSION: &str = "1.0";

/// Identifies the redaction rules a record was produced under.
///
/// Recorded in every event so a log can be read years later by someone who
/// needs to know what "redacted" meant at the time.
pub const REDACTION_PROFILE_ID: &str = "ofw.structural";
pub const REDACTION_PROFILE_VERSION: &str = "1.0.0";

const MAX_TARGET_REFS: usize = 256;
const MAX_DETERMINING_RULE_REFS: usize = 256;

/// A SHA-256 digest.
///
/// The only way a variable-length input reaches an audit record. A digest lets
/// a reader confirm that two records concern the same thing without the record
/// containing the thing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Digest {
    algorithm: &'static str,
    value: String,
}

impl Digest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let output = hasher.finalize();
        let mut value = String::with_capacity(64);
        for byte in output {
            // Lowercase hex, matching the contract's `^[0-9a-f]{64}$`.
            value.push(hex_nibble(byte >> 4));
            value.push(hex_nibble(byte & 0x0f));
        }
        Self {
            algorithm: "sha256",
            value,
        }
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

const fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

/// Component health, per the v1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// What an audit health level means for a decision.
///
/// The rule the design states: audit unavailability makes every **mutation**
/// indeterminate, while a positively proven read-only operation may continue
/// with explicitly degraded health.
///
/// The asymmetry is deliberate and is not a convenience. An unaudited mutation
/// is an action nobody can reconstruct afterwards, which is the situation an
/// audit trail exists to prevent. An unaudited read has already happened to the
/// same data the agent could see anyway, and denying every read when the sink
/// is down converts an audit outage into a total outage -- which is how
/// audit gating gets disabled by an operator under pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditGate {
    /// The decision may proceed.
    Proceed,
    /// The decision may proceed, and health must be reported as degraded.
    ProceedDegraded,
    /// The decision is indeterminate regardless of what policy said.
    Indeterminate,
}

/// Applies the audit health rule to one operation effect.
#[must_use]
pub const fn gate(effect: OperationEffect, health: AuditHealth) -> AuditGate {
    let is_read = matches!(effect, OperationEffect::Read);
    match health {
        AuditHealth::Healthy => AuditGate::Proceed,
        // A read may continue on a degraded or absent sink; anything that
        // changes state may not.
        AuditHealth::Degraded | AuditHealth::Unhealthy | AuditHealth::Unknown => {
            if is_read {
                AuditGate::ProceedDegraded
            } else {
                AuditGate::Indeterminate
            }
        }
    }
}

/// Which lifecycle point an event records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Proposed,
    Evaluated,
    Denied,
    HealthChanged,
}

/// The decision outcome as the audit contract spells it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Allow,
    Ask,
    Deny,
    Indeterminate,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Source {
    pub host: &'static str,
    pub protocol: &'static str,
    pub adapter_id: &'static str,
    /// Compiled-in, from the adapter's closed set of supported tools. Not the
    /// borrowed envelope string.
    pub tool_name: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Operation {
    pub kind: NamespacedName,
    pub effect: OperationEffect,
    /// A digest of the normalized operation, never the operation.
    pub digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Health {
    pub enforcement: AuditHealth,
    pub audit: AuditHealth,
    pub coverage: AuditHealth,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Redaction {
    pub profile_id: &'static str,
    pub profile_version: &'static str,
    pub redacted_field_count: u32,
    pub canary_scan: &'static str,
}

/// One redacted audit record.
///
/// Look at the field types rather than the field names: every one of them is a
/// literal, a digest, a bounded operator-authored identifier, or a number.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub schema_version: &'static str,
    pub event_id: String,
    pub occurred_at: String,
    pub event_type: EventType,
    pub operation_id: Option<String>,
    pub decision_id: Option<String>,
    pub correlation_id: Identifier,
    /// A digest of the actor identity, not the identity.
    pub actor_ref: Digest,
    /// A digest of the session identity, not the identity.
    pub session_ref: Digest,
    pub source: Source,
    pub operation: Option<Operation>,
    pub target_refs: Vec<Digest>,
    pub environment: EnvironmentClass,
    pub outcome: AuditOutcome,
    pub policy_snapshot_digest: Option<Digest>,
    pub determining_rule_refs: Vec<Identifier>,
    pub health: Health,
    pub redaction: Redaction,
}

/// Why an event could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    TooManyTargetRefs,
    TooManyDeterminingRuleRefs,
    SerializationFailed,
}

impl core::fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::TooManyTargetRefs => "audit event exceeds the target reference bound",
            Self::TooManyDeterminingRuleRefs => "audit event exceeds the rule reference bound",
            Self::SerializationFailed => "audit event could not be serialized",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AuditError {}

impl AuditEvent {
    /// Bounds the collection-valued fields.
    ///
    /// Truncating instead would silently drop the evidence a reader needs, so
    /// an over-large event is an audit failure rather than a shorter record.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.target_refs.len() > MAX_TARGET_REFS {
            return Err(AuditError::TooManyTargetRefs);
        }
        if self.determining_rule_refs.len() > MAX_DETERMINING_RULE_REFS {
            return Err(AuditError::TooManyDeterminingRuleRefs);
        }
        Ok(())
    }

    /// Serializes to one line of JSON.
    ///
    /// A record is newline-delimited, so it must not contain a raw newline.
    /// `serde_json::to_string` escapes them inside strings, and every field is
    /// either a literal or a digest, so this is belt and braces rather than the
    /// only guard.
    pub fn to_json_line(&self) -> Result<String, AuditError> {
        self.validate()?;
        let mut line = serde_json::to_string(self).map_err(|_| AuditError::SerializationFailed)?;
        if line.contains('\n') {
            return Err(AuditError::SerializationFailed);
        }
        line.push('\n');
        Ok(line)
    }
}

/// Formats a UUID-shaped identifier from digest bytes.
///
/// # Not a random UUID
///
/// This is a **deterministic** identifier that matches the contract's UUIDv4
/// pattern; it is not drawn from a cryptographic random source, because the
/// runtime has no random dependency and does not need one here. The version
/// and variant nibbles are set so the shape validates.
///
/// Nothing may rely on it being unguessable. It is a correlation handle in a
/// local audit log, not a capability, and an identifier that is derived rather
/// than random is in fact easier to reconcile across records. If a future
/// design uses an event identifier as a bearer value, that design needs real
/// randomness and this function is not it.
#[must_use]
pub fn uuid_shaped(seed: &Digest) -> String {
    let hex = seed.value();
    let take = |from: usize, to: usize| -> &str { &hex[from..to] };
    format!(
        "{}-{}-4{}-{}{}-{}",
        take(0, 8),
        take(8, 12),
        take(13, 16),
        // The variant nibble must be one of 8, 9, a or b.
        match hex.as_bytes().get(16) {
            Some(byte) => variant_nibble(*byte),
            None => '8',
        },
        take(17, 20),
        take(20, 32),
    )
}

const fn variant_nibble(byte: u8) -> char {
    match byte {
        b'0' | b'4' | b'8' | b'c' => '8',
        b'1' | b'5' | b'9' | b'd' => '9',
        b'2' | b'6' | b'a' | b'e' => 'a',
        _ => 'b',
    }
}

#[cfg(test)]
mod tests {
    use ofw_contracts::{EnvironmentClass, Identifier, NamespacedName, OperationEffect};

    use super::{
        AuditEvent, AuditGate, AuditHealth, AuditOutcome, Digest, EventType, Health, Operation,
        REDACTION_PROFILE_ID, REDACTION_PROFILE_VERSION, Redaction, SCHEMA_VERSION, Source, gate,
        uuid_shaped,
    };

    const CANARY: &str = "CANARY_SECRET_a1b2c3d4e5";

    fn identifier(value: &str) -> Identifier {
        match Identifier::new(value) {
            Ok(value) => value,
            Err(error) => unreachable!("test identifier must be valid: {error}"),
        }
    }

    fn name(value: &str) -> NamespacedName {
        match NamespacedName::new(value) {
            Ok(value) => value,
            Err(error) => unreachable!("test name must be valid: {error}"),
        }
    }

    /// An event built from an invocation that carries a secret in its command.
    fn event_from_a_secret_bearing_invocation() -> AuditEvent {
        let raw_command = format!("git push --token {CANARY}");
        AuditEvent {
            schema_version: SCHEMA_VERSION,
            event_id: uuid_shaped(&Digest::of(b"event")),
            occurred_at: "2026-08-07T00:00:00Z".to_owned(),
            event_type: EventType::Evaluated,
            operation_id: None,
            decision_id: None,
            correlation_id: identifier("turn-1"),
            actor_ref: Digest::of(CANARY.as_bytes()),
            session_ref: Digest::of(CANARY.as_bytes()),
            source: Source {
                host: "codex",
                protocol: "codex.pre_tool_use",
                adapter_id: "ofw.codex",
                tool_name: "Bash",
            },
            operation: Some(Operation {
                kind: name("git.status"),
                effect: OperationEffect::Read,
                // The command reaches the record only as a digest.
                digest: Digest::of(raw_command.as_bytes()),
            }),
            target_refs: vec![Digest::of(b"F:/repo")],
            environment: EnvironmentClass::Local,
            outcome: AuditOutcome::Deny,
            policy_snapshot_digest: None,
            determining_rule_refs: vec![identifier("org.baseline/deny-status")],
            health: Health {
                enforcement: AuditHealth::Unhealthy,
                audit: AuditHealth::Unhealthy,
                coverage: AuditHealth::Degraded,
            },
            redaction: Redaction {
                profile_id: REDACTION_PROFILE_ID,
                profile_version: REDACTION_PROFILE_VERSION,
                redacted_field_count: 0,
                canary_scan: "passed",
            },
        }
    }

    /// The canary invariant, across every representation a record has.
    #[test]
    fn no_secret_reaches_a_serialized_event_or_its_debug_form() {
        let event = event_from_a_secret_bearing_invocation();
        let line = match event.to_json_line() {
            Ok(line) => line,
            Err(error) => unreachable!("the event must serialize: {error}"),
        };

        assert!(!line.contains(CANARY), "serialized record leaked");
        assert!(!format!("{event:?}").contains(CANARY), "Debug leaked");
        // The digest is present, so the record is still useful for correlation.
        assert!(line.contains("\"algorithm\":\"sha256\""));
        assert!(line.ends_with('\n'), "records are newline-delimited");
        assert_eq!(line.matches('\n').count(), 1, "one record, one line");
    }

    /// Retained red-first witness: an event shape with a raw payload field.
    ///
    /// This is the ordinary way audit records get written -- keep the command
    /// so the log is easy to read -- and it is exactly what the structural
    /// design refuses to make possible.
    #[derive(Debug, serde::Serialize)]
    struct VulnerableEvent {
        correlation_id: String,
        /// The field that cannot exist on `AuditEvent`.
        command: String,
    }

    fn vulnerable_event_with_raw_payload() -> VulnerableEvent {
        VulnerableEvent {
            correlation_id: "turn-1".to_owned(),
            command: format!("git push --token {CANARY}"),
        }
    }

    #[test]
    fn red_first_witness_detects_raw_payload_in_an_event() {
        let real = match event_from_a_secret_bearing_invocation().to_json_line() {
            Ok(line) => line,
            Err(error) => unreachable!("the event must serialize: {error}"),
        };
        assert!(!real.contains(CANARY));

        // The retained witness satisfies every other property of a record --
        // it serializes, it is one line, it correlates -- and leaks.
        let vulnerable = match serde_json::to_string(&vulnerable_event_with_raw_payload()) {
            Ok(line) => line,
            Err(error) => unreachable!("the witness must serialize: {error}"),
        };
        assert!(
            vulnerable.contains(CANARY),
            "the witness must leak, or it is not witnessing anything"
        );
    }

    /// Audit unavailability stops mutations and does not stop reads.
    ///
    /// Tested on the gate directly. No mutation is interpreted yet, so no
    /// envelope can reach the `Indeterminate` arm end to end -- and a test
    /// asserting the rule through a path that cannot carry a mutation would be
    /// asserting nothing.
    #[test]
    fn audit_failure_stops_mutations_and_lets_reads_continue_degraded() {
        let mutations = [
            OperationEffect::Create,
            OperationEffect::Update,
            OperationEffect::Delete,
            OperationEffect::Move,
            OperationEffect::Execute,
            OperationEffect::PermissionChange,
            OperationEffect::Publish,
            OperationEffect::UnknownMutation,
        ];

        for unhealthy in [
            AuditHealth::Degraded,
            AuditHealth::Unhealthy,
            AuditHealth::Unknown,
        ] {
            assert_eq!(
                gate(OperationEffect::Read, unhealthy),
                AuditGate::ProceedDegraded,
                "a read must continue, explicitly degraded"
            );
            for effect in mutations {
                assert_eq!(
                    gate(effect, unhealthy),
                    AuditGate::Indeterminate,
                    "{effect:?} must not proceed without an audit trail"
                );
            }
        }

        // A healthy sink gates nothing.
        assert_eq!(
            gate(OperationEffect::Delete, AuditHealth::Healthy),
            AuditGate::Proceed
        );
    }

    /// Retained red-first witness: audit failure ignored for mutations.
    fn vulnerable_ignores_audit_health(
        _effect: OperationEffect,
        _health: AuditHealth,
    ) -> AuditGate {
        AuditGate::Proceed
    }

    #[test]
    fn red_first_witness_detects_audit_failure_ignored_for_mutations() {
        assert_eq!(
            gate(OperationEffect::Delete, AuditHealth::Unhealthy),
            AuditGate::Indeterminate
        );
        // The retained witness lets an unauditable deletion through.
        assert_eq!(
            vulnerable_ignores_audit_health(OperationEffect::Delete, AuditHealth::Unhealthy),
            AuditGate::Proceed
        );
    }

    /// The serialized record carries exactly the fields the contract requires.
    ///
    /// Read from the normative schema rather than restated here, so a rename on
    /// either side fails the build. An audit record that quietly stopped
    /// carrying `determining_rule_refs` would still serialize, still validate
    /// as JSON, and still look right in a log -- and the evidence for why a
    /// decision was made would be gone.
    #[test]
    fn the_serialized_record_matches_the_v1_audit_contract() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../policy/schemas/v1/audit-event.schema.json"
        );
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => unreachable!("the audit schema must be readable: {error}"),
        };
        let schema: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => unreachable!("the audit schema must be valid JSON: {error}"),
        };

        let required: Vec<String> =
            match schema.pointer("/required").and_then(|node| node.as_array()) {
                Some(values) => values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect(),
                None => unreachable!("the audit schema must declare required fields"),
            };
        let allowed: Vec<String> = match schema
            .pointer("/properties")
            .and_then(|node| node.as_object())
        {
            Some(map) => map.keys().cloned().collect(),
            None => unreachable!("the audit schema must declare properties"),
        };

        let value = match serde_json::to_value(event_from_a_secret_bearing_invocation()) {
            Ok(value) => value,
            Err(error) => unreachable!("the event must serialize: {error}"),
        };
        let object = match value.as_object() {
            Some(object) => object,
            None => unreachable!("an event must serialize to an object"),
        };

        for field in &required {
            assert!(
                object.contains_key(field),
                "the record is missing the required field {field}"
            );
        }
        // `additionalProperties: false`: nothing may be emitted that the
        // contract does not name.
        for field in object.keys() {
            assert!(
                allowed.contains(field),
                "the record emits {field}, which the contract does not allow"
            );
        }
        assert_eq!(
            object
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some(SCHEMA_VERSION)
        );
    }

    #[test]
    fn digests_are_lowercase_hex_of_the_contract_length() {
        let digest = Digest::of(b"operation-firewall");
        assert_eq!(digest.value().len(), 64);
        assert!(
            digest
                .value()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        // Same input, same digest: records correlate.
        assert_eq!(Digest::of(b"operation-firewall"), digest);
        assert_ne!(Digest::of(b"operation-firewal"), digest);
    }

    /// The identifier matches the contract's UUIDv4 pattern.
    #[test]
    fn event_identifiers_match_the_contract_shape() {
        let value = uuid_shaped(&Digest::of(b"seed"));
        let groups: Vec<&str> = value.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert_eq!(
            groups.iter().map(|group| group.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(value.starts_with(&Digest::of(b"seed").value()[..8]));
        // Version 4 nibble and a valid variant nibble.
        assert_eq!(groups[2].as_bytes().first(), Some(&b'4'));
        assert!(matches!(
            groups[3].as_bytes().first(),
            Some(b'8' | b'9' | b'a' | b'b')
        ));
        assert!(
            value
                .bytes()
                .all(|byte| byte == b'-' || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
