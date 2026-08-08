//! Audit persistence: exclusive append, rotation, and crash recovery.
//!
//! These use real files under the system temporary directory, because the
//! properties under test are filesystem properties. An in-memory double would
//! prove that the code calls the functions it calls.

use std::path::{Path, PathBuf};

use ofw_audit::{
    AuditEvent, AuditHealth, AuditOutcome, AuditSink, Digest, EventType, Health, Redaction,
    SinkError, Source, read_segment,
};
use ofw_contracts::{EnvironmentClass, Identifier};

fn directory(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("ofw-audit-{}-{label}", std::process::id()));
    // Start each case from a clean directory so a previous run cannot make a
    // test pass. Scoped to this crate's own temp prefix.
    let _ = std::fs::remove_dir_all(&path);
    match std::fs::create_dir_all(&path) {
        Ok(()) => path,
        Err(error) => unreachable!("test directory must be creatable: {error}"),
    }
}

fn identifier(value: &str) -> Identifier {
    match Identifier::new(value) {
        Ok(value) => value,
        Err(error) => unreachable!("test identifier must be valid: {error}"),
    }
}

fn event(correlation: &str) -> AuditEvent {
    AuditEvent {
        schema_version: ofw_audit::SCHEMA_VERSION,
        event_id: ofw_audit::uuid_shaped(&Digest::of(correlation.as_bytes())),
        occurred_at: "2026-08-07T00:00:00Z".to_owned(),
        event_type: EventType::Evaluated,
        operation_id: None,
        decision_id: None,
        correlation_id: identifier(correlation),
        actor_ref: Digest::of(b"actor"),
        session_ref: Digest::of(b"session"),
        source: Source {
            host: "codex",
            protocol: "codex.pre_tool_use",
            adapter_id: "ofw.codex",
            tool_name: "Bash",
        },
        operation: None,
        target_refs: Vec::new(),
        environment: EnvironmentClass::Local,
        outcome: AuditOutcome::Deny,
        policy_snapshot_digest: None,
        determining_rule_refs: Vec::new(),
        health: Health {
            enforcement: AuditHealth::Degraded,
            audit: AuditHealth::Healthy,
            coverage: AuditHealth::Degraded,
        },
        redaction: Redaction {
            profile_id: ofw_audit::REDACTION_PROFILE_ID,
            profile_version: ofw_audit::REDACTION_PROFILE_VERSION,
            redacted_field_count: 0,
            canary_scan: "passed",
        },
    }
}

fn open(directory: &Path) -> AuditSink {
    match AuditSink::open(directory, None) {
        Ok(sink) => sink,
        Err(error) => unreachable!("the sink must open: {error}"),
    }
}

#[test]
fn records_append_one_per_line() {
    let path = directory("append");
    let sink = open(&path);

    for index in 0..5 {
        match sink.append(&event(&format!("turn-{index}"))) {
            Ok(()) => {}
            Err(error) => unreachable!("append must succeed: {error}"),
        }
    }

    let lines = read_segment(&sink.active_segment());
    assert_eq!(lines.len(), 5, "one line per record");
    for line in &lines {
        // Each line must be independently parseable. A reader recovering a
        // damaged trail reads line by line, so a record that only parses in
        // the context of its neighbours is not a record.
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => assert!(value.get("schema_version").is_some()),
            Err(error) => unreachable!("each line must be valid JSON: {error}"),
        }
    }
    assert_eq!(sink.health(), AuditHealth::Healthy);
}

/// Concurrent writers must not interleave.
///
/// The spec names concurrency tests for audit writers, and this is the failure
/// they exist to catch: two processes appending at once producing one corrupt
/// line and losing both records. Threads rather than processes because the lock
/// is filesystem-based and therefore shared either way, and threads make the
/// contention tighter than process startup would.
#[test]
fn concurrent_writers_do_not_interleave() {
    let path = directory("concurrent");
    let writers = 8;
    let per_writer = 12;

    let handles: Vec<_> = (0..writers)
        .map(|writer| {
            let path = path.clone();
            std::thread::spawn(move || {
                let sink = open(&path);
                for index in 0..per_writer {
                    match sink.append(&event(&format!("w{writer}-{index}"))) {
                        Ok(()) => {}
                        Err(error) => unreachable!("concurrent append must succeed: {error}"),
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => unreachable!("a writer thread panicked"),
        }
    }

    let lines = read_segment(&path.join("audit.jsonl"));
    assert_eq!(
        lines.len(),
        writers * per_writer,
        "every record must survive"
    );
    // Every line parses: an interleaved write would produce at least one that
    // does not, and counting lines alone would not catch it.
    let mut correlations = Vec::new();
    for line in &lines {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => correlations.push(
                value
                    .get("correlation_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ),
            Err(error) => unreachable!("interleaved write corrupted a line: {error}"),
        }
    }
    correlations.sort();
    correlations.dedup();
    assert_eq!(
        correlations.len(),
        writers * per_writer,
        "no record may be lost or duplicated"
    );
}

/// A damaged trailing record is moved aside rather than left to be read.
///
/// A truncated record still looks like evidence, which is worse than losing it.
#[test]
fn a_partial_final_record_is_quarantined_and_reported() {
    let path = directory("quarantine");
    let sink = open(&path);
    match sink.append(&event("intact")) {
        Ok(()) => {}
        Err(error) => unreachable!("append must succeed: {error}"),
    }

    // Simulate a crash mid-write: a final line with no terminating newline.
    let segment = sink.active_segment();
    let mut contents = match std::fs::read_to_string(&segment) {
        Ok(contents) => contents,
        Err(error) => unreachable!("segment must be readable: {error}"),
    };
    contents.push_str(r#"{"schema_version":"1.0","correlation_id":"trunc"#);
    match std::fs::write(&segment, &contents) {
        Ok(()) => {}
        Err(error) => unreachable!("segment must be writable: {error}"),
    }

    let recovered = open(&path);
    assert_eq!(
        recovered.health(),
        AuditHealth::Degraded,
        "recovery must report degraded health, not silently repair"
    );

    let lines = read_segment(&segment);
    assert_eq!(lines.len(), 1, "the intact record survives");
    let Some(survivor) = lines.first() else {
        unreachable!("the intact record must survive")
    };
    assert!(survivor.contains("intact"));
    assert!(
        !survivor.contains("trunc"),
        "the damaged record must not remain in the active segment"
    );

    // The damaged bytes are kept, not discarded: they may be the only trace of
    // what was happening when the process died.
    let quarantined: Vec<_> = match std::fs::read_dir(&path) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("quarantine"))
            .collect(),
        Err(error) => unreachable!("directory must be readable: {error}"),
    };
    assert_eq!(quarantined.len(), 1, "the damaged bytes must be retained");
}

#[test]
fn an_intact_segment_is_not_quarantined() {
    let path = directory("intact");
    let sink = open(&path);
    match sink.append(&event("one")) {
        Ok(()) => {}
        Err(error) => unreachable!("append must succeed: {error}"),
    }
    assert_eq!(open(&path).health(), AuditHealth::Healthy);
}

/// Audit records may not live inside the repository they audit.
#[test]
fn the_sink_refuses_a_directory_inside_the_repository() {
    let boundary = directory("repo");
    let inside = boundary.join("audit");
    match std::fs::create_dir_all(&inside) {
        Ok(()) => {}
        Err(error) => unreachable!("test directory must be creatable: {error}"),
    }

    assert_eq!(
        AuditSink::open(&inside, Some(&boundary)),
        Err(SinkError::DirectoryInsideRepository)
    );
    // The same directory is fine when it is not inside the boundary given.
    let elsewhere = directory("repo-elsewhere");
    assert!(AuditSink::open(&inside, Some(&elsewhere)).is_ok());
}

#[test]
fn a_missing_directory_is_an_error_rather_than_a_silent_no_op() {
    let mut absent = directory("absent");
    absent.push("no-such-directory");
    assert_eq!(
        AuditSink::open(&absent, None),
        Err(SinkError::DirectoryUnusable)
    );
}

/// Retained red-first witness: a sink that swallows its own write failure.
///
/// The dangerous shape is not a sink that fails -- it is one that reports
/// success when nothing was written, because the caller then reports healthy
/// audit and a mutation proceeds unrecorded.
fn vulnerable_swallows_write_failure(_event: &AuditEvent) -> Result<(), SinkError> {
    Ok(())
}

#[test]
fn red_first_witness_detects_a_sink_that_swallows_failures() {
    let mut absent = directory("swallow");
    absent.push("no-such-directory");

    // The real sink cannot even be opened against a missing directory, so
    // there is no way to be told a record was written when it was not.
    assert_eq!(
        AuditSink::open(&absent, None),
        Err(SinkError::DirectoryUnusable)
    );
    // The retained witness reports success while writing nothing at all.
    assert_eq!(vulnerable_swallows_write_failure(&event("ghost")), Ok(()));
}
