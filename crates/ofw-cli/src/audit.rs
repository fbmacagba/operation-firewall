//! Turning one assessment into one persisted audit record.
//!
//! The event is assembled from the assessment's own payload-free fields and
//! nothing else. Every value written here is a compiled-in literal, a digest
//! the pipeline already computed, or a bounded identifier derived from one --
//! so this module has no opportunity to reintroduce a payload that
//! `ofw-audit`'s type deliberately cannot hold.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ofw_audit::{
    AuditEvent, AuditHealth, AuditOutcome, AuditSink, EventType, Health, REDACTION_PROFILE_ID,
    REDACTION_PROFILE_VERSION, Redaction, SCHEMA_VERSION, Source,
};
use ofw_contracts::EnvironmentClass;
use ofw_core::DecisionOutcome;

use crate::pipeline::Assessment;

/// Opens the sink for a configured audit directory.
///
/// A deployment with no audit directory has no trail, which is
/// [`AuditHealth::Unhealthy`] rather than an error: not configuring auditing is
/// a choice, and the consequence -- mutations refuse -- is applied rather than
/// warned about. A directory that *is* configured and does not work is also
/// unhealthy, and for the stronger reason that someone asked for a trail and
/// is not getting one.
#[must_use]
pub fn open_sink(
    directory: Option<&Path>,
    repository_boundary: Option<&Path>,
) -> (Option<AuditSink>, AuditHealth) {
    let Some(directory) = directory else {
        return (None, AuditHealth::Unhealthy);
    };
    match AuditSink::open(directory, repository_boundary) {
        Ok(sink) => {
            let health = sink.health();
            (Some(sink), health)
        }
        Err(_) => (None, AuditHealth::Unhealthy),
    }
}

/// Records one decision, returning the health to report afterwards.
///
/// A write that fails downgrades health rather than being ignored. The caller
/// has already been told what the decision is; what changes is whether the
/// system can claim the decision was recorded.
#[must_use]
pub fn record(
    sink: Option<&AuditSink>,
    assessment: &Assessment,
    environment: EnvironmentClass,
    health: AuditHealth,
) -> AuditHealth {
    let Some(sink) = sink else {
        return health;
    };

    let event = build(assessment, environment, health);
    match sink.append(&event) {
        Ok(()) => health,
        // The decision stands; the claim that it was recorded does not.
        Err(_) => AuditHealth::Unhealthy,
    }
}

fn build(
    assessment: &Assessment,
    environment: EnvironmentClass,
    audit_health: AuditHealth,
) -> AuditEvent {
    let references = &assessment.references;
    AuditEvent {
        schema_version: SCHEMA_VERSION,
        event_id: ofw_audit::uuid_shaped(&references.invocation),
        occurred_at: timestamp(),
        event_type: match assessment.outcome {
            DecisionOutcome::Deny => EventType::Denied,
            _ => EventType::Evaluated,
        },
        operation_id: None,
        decision_id: None,
        correlation_id: references.correlation.clone(),
        // No actor identity is established yet; the session digest stands in
        // rather than a field being invented that implies one was.
        actor_ref: references.session.clone(),
        session_ref: references.session.clone(),
        source: Source {
            host: "codex",
            protocol: "codex.pre_tool_use",
            adapter_id: "ofw.codex",
            tool_name: assessment.tool_name.unwrap_or("unknown"),
        },
        // Populated once the operation kind is a resolved contract name rather
        // than a compiled-in literal; recording a partial operation block would
        // claim more structure than was established.
        operation: None,
        target_refs: Vec::new(),
        environment,
        outcome: match assessment.outcome {
            DecisionOutcome::Allow => AuditOutcome::Allow,
            DecisionOutcome::Ask => AuditOutcome::Ask,
            DecisionOutcome::Deny => AuditOutcome::Deny,
            DecisionOutcome::Indeterminate => AuditOutcome::Indeterminate,
        },
        policy_snapshot_digest: None,
        determining_rule_refs: Vec::new(),
        health: Health {
            enforcement: AuditHealth::Degraded,
            audit: audit_health,
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

/// An RFC 3339 UTC timestamp, formatted without a date library.
///
/// Derived from the civil-from-days algorithm rather than approximated: an
/// audit record whose timestamps drift is one whose ordering cannot be trusted
/// against anything else. A clock that reads before the epoch is reported as
/// the epoch rather than as a negative value, because a wrong-but-parseable
/// timestamp is easier to notice than a malformed one.
fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());

    let days = (seconds / 86_400) as i64;
    let time_of_day = seconds % 86_400;
    let (hour, minute, second) = (
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60,
    );

    // Howard Hinnant's civil_from_days, shifted to a March-based year so leap
    // days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::timestamp;

    /// The timestamp must satisfy the contract's `date-time` shape and bound.
    ///
    /// Checked structurally rather than against a fixed value, because the
    /// clock moves. What is pinned is the format and that it lands in a
    /// plausible era -- a conversion bug typically produces year 1970 or a
    /// five-digit year, and both are visible here.
    #[test]
    fn the_timestamp_matches_the_contract_shape() {
        let value = timestamp();
        assert_eq!(value.len(), 20, "got {value}");
        assert!(value.ends_with('Z'));

        let bytes = value.as_bytes();
        for index in [4, 7] {
            assert_eq!(bytes[index], b'-', "got {value}");
        }
        assert_eq!(bytes[10], b'T');
        for index in [13, 16] {
            assert_eq!(bytes[index], b':', "got {value}");
        }
        for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
            assert!(bytes[index].is_ascii_digit(), "got {value}");
        }

        let year: u32 = match value[..4].parse() {
            Ok(year) => year,
            Err(error) => unreachable!("the year must parse: {error}"),
        };
        assert!(
            (2020..2200).contains(&year),
            "the epoch conversion looks wrong: {value}"
        );
        let month: u32 = match value[5..7].parse() {
            Ok(month) => month,
            Err(error) => unreachable!("the month must parse: {error}"),
        };
        let day: u32 = match value[8..10].parse() {
            Ok(day) => day,
            Err(error) => unreachable!("the day must parse: {error}"),
        };
        assert!((1..=12).contains(&month), "got {value}");
        assert!((1..=31).contains(&day), "got {value}");
    }
}
