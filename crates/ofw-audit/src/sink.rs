//! Append-only audit persistence.
//!
//! # What this is responsible for
//!
//! Getting a record onto disk such that a later reader can tell the difference
//! between "this operation was not audited" and "this operation was audited and
//! the record says X". Those are different claims, and a sink that cannot
//! distinguish them is not an audit trail.
//!
//! Three properties carry that, and each is a specific failure this guards:
//!
//! - **Exclusive append.** Two hook processes can run at once — a host may
//!   evaluate tool calls in parallel — and two interleaved writes produce one
//!   corrupt line and lose both records.
//! - **A record is a whole line or it is not there.** A partially written final
//!   line is the normal result of a crash or a full disk. On the next open it
//!   is moved aside rather than left where a reader would parse the surviving
//!   prefix as a complete record.
//! - **Failure is typed and loud.** Every failure returns an error the caller
//!   turns into degraded or unhealthy audit health. There is no path where a
//!   write silently does not happen.
//!
//! # What this deliberately does not do
//!
//! **Retention.** Retention deletes closed segments, and deleting audit
//! evidence is the one operation in this crate that cannot be undone or
//! reviewed after the fact. It is left unimplemented rather than implemented
//! carefully, because the cost of getting it wrong is unbounded and the cost of
//! not having it is disk usage.
//!
//! **Ownership and permission verification.** The design requires startup to
//! verify that the audit directory has the expected owner and mode and to
//! reject insecure paths. Doing that properly is per-platform and, on Windows,
//! needs APIs this workspace's `forbid(unsafe_code)` does not admit. What is
//! checked instead is narrower and stated as such: the directory must exist, be
//! a directory, and be writable, and the caller is expected to keep it outside
//! the untrusted repository.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::{AuditError, AuditEvent, AuditHealth};

/// Whether appending a line of this size should rotate the active segment
/// first.
///
/// Separated from the filesystem so the rule itself is testable without
/// writing eight megabytes, exactly as `permissions_are_exclusive` is separated
/// from the syscall that supplies its input. Both conditions are load-bearing
/// and they fail differently: without the size check a segment grows without
/// bound, and without the `existing > 0` check an empty segment rotates on its
/// first write, producing an empty closed segment and a reader who cannot tell
/// rotation from data loss.
#[must_use]
pub const fn should_rotate(existing: u64, line: usize) -> bool {
    let projected = existing.saturating_add(line as u64);
    existing > 0 && projected > MAX_SEGMENT_BYTES
}

/// Whether a lock held for this long may be broken.
///
/// Separated for the same reason: asserting the stale branch through the
/// filesystem would need control over a file's modification time, so the rule
/// would go untested and only the "fresh" answer would ever be observed.
///
/// Breaking a lock too early lets two processes append at once; breaking it too
/// late strands every later decision behind a dead process. Neither direction
/// is safe, which is why the boundary is pinned rather than the direction.
#[must_use]
pub const fn elapsed_is_stale(elapsed: Duration) -> bool {
    elapsed.as_secs() > LOCK_STALE_AFTER.as_secs()
}

/// The active segment. Closed segments are numbered beside it.
const ACTIVE_SEGMENT: &str = "audit.jsonl";
const LOCK_FILE: &str = "audit.lock";

/// Rotate before a segment grows past this. Size-based, not time-based: a
/// reader needs a bounded file, and time says nothing about size.
pub const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;

/// One record may not exceed this. A record too large to write is an audit
/// failure, never a truncated record: a truncated record is indistinguishable
/// from a crash-damaged one.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// How long to keep trying for the lock before giving up.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_POLL: Duration = Duration::from_millis(25);

/// A lock older than this is treated as abandoned.
///
/// A process killed between creating the lock and removing it would otherwise
/// wedge auditing permanently, and because audit failure denies mutations, a
/// wedged lock becomes a denial of service that outlives the crash. Breaking a
/// stale lock trades a small, bounded race — two writers who both decide the
/// same lock is stale within the same instant — against an unbounded outage.
/// The trade is stated rather than hidden: interleaving is possible in that
/// window, and the quarantine path is what catches its result.
const LOCK_STALE_AFTER: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkError {
    /// The configured directory is missing, is not a directory, or cannot be
    /// written to.
    DirectoryUnusable,
    /// The audit directory is inside the repository it audits.
    DirectoryInsideRepository,
    LockUnavailable,
    RecordTooLarge,
    WriteFailed,
    RotationFailed,
    /// The record was written, and a damaged record from a previous run was
    /// found and quarantined. Auditing works; health is degraded.
    QuarantinedPriorRecord,
}

impl core::fmt::Display for SinkError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::DirectoryUnusable => "audit directory is missing or not writable",
            Self::DirectoryInsideRepository => "audit directory is inside the repository it audits",
            Self::LockUnavailable => "audit lock could not be acquired",
            Self::RecordTooLarge => "audit record exceeds the configured byte limit",
            Self::WriteFailed => "audit record could not be written",
            Self::RotationFailed => "audit segment could not be rotated",
            Self::QuarantinedPriorRecord => "a damaged audit record was quarantined",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SinkError {}

impl From<AuditError> for SinkError {
    fn from(_: AuditError) -> Self {
        Self::WriteFailed
    }
}

/// An append-only audit sink over a directory of JSONL segments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSink {
    directory: PathBuf,
    health: AuditHealth,
}

impl AuditSink {
    /// Opens the sink, recovering from a damaged final record if there is one.
    ///
    /// `repository_boundary` is refused as an ancestor of the audit directory.
    /// Audit records written inside the repository being audited are writable
    /// by whatever the repository can influence, which is the thing the records
    /// exist to be independent of.
    pub fn open(directory: &Path, repository_boundary: Option<&Path>) -> Result<Self, SinkError> {
        if !directory.is_dir() {
            return Err(SinkError::DirectoryUnusable);
        }
        if let Some(boundary) = repository_boundary {
            // Compared canonically for the same reason containment is
            // elsewhere: a lexical check is defeated by traversal and links.
            let audit =
                std::fs::canonicalize(directory).map_err(|_| SinkError::DirectoryUnusable)?;
            if let Ok(boundary) = std::fs::canonicalize(boundary)
                && audit.starts_with(&boundary)
            {
                return Err(SinkError::DirectoryInsideRepository);
            }
        }

        let sink = Self {
            directory: directory.to_path_buf(),
            health: AuditHealth::Healthy,
        };

        match sink.quarantine_partial_record()? {
            true => Ok(Self {
                health: AuditHealth::Degraded,
                ..sink
            }),
            false => Ok(sink),
        }
    }

    #[must_use]
    pub const fn health(&self) -> AuditHealth {
        self.health
    }

    #[must_use]
    pub fn active_segment(&self) -> PathBuf {
        self.directory.join(ACTIVE_SEGMENT)
    }

    /// Appends one record, rotating first if it would not fit.
    pub fn append(&self, event: &AuditEvent) -> Result<(), SinkError> {
        let line = event.to_json_line()?;
        if line.len() > MAX_RECORD_BYTES {
            return Err(SinkError::RecordTooLarge);
        }

        let _guard = LockGuard::acquire(&self.directory)?;

        let path = self.active_segment();
        let existing = std::fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if should_rotate(existing, line.len()) {
            self.rotate(&path)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|_| SinkError::WriteFailed)?;
        // One `write_all` for the whole line including its newline. Under the
        // lock this is already exclusive; doing it in one call also means a
        // crash mid-write leaves a prefix rather than a record split across
        // two syscalls whose interleaving would be harder to reason about.
        file.write_all(line.as_bytes())
            .map_err(|_| SinkError::WriteFailed)?;
        // Durability before the lock is released. A record that is only in the
        // page cache when the machine loses power is a record that does not
        // exist, and the caller has already been told the write succeeded.
        file.sync_all().map_err(|_| SinkError::WriteFailed)?;
        Ok(())
    }

    /// Renames the active segment out of the way, atomically and in place.
    ///
    /// Same-directory rename so it cannot cross a filesystem boundary and
    /// degrade into a copy-then-delete, which is not atomic and can lose the
    /// segment if it fails halfway.
    fn rotate(&self, active: &Path) -> Result<(), SinkError> {
        for index in 1..10_000u32 {
            let candidate = self.directory.join(format!("audit.{index}.jsonl"));
            if candidate.exists() {
                continue;
            }
            return std::fs::rename(active, &candidate).map_err(|_| SinkError::RotationFailed);
        }
        Err(SinkError::RotationFailed)
    }

    /// Moves a damaged trailing record aside, if there is one.
    ///
    /// Returns whether anything was quarantined. A final line without a
    /// terminating newline is the signature of a write that did not finish;
    /// leaving it in place would let a reader parse the surviving prefix as a
    /// complete record, which is worse than losing it, because a truncated
    /// record still looks like evidence.
    fn quarantine_partial_record(&self) -> Result<bool, SinkError> {
        let path = self.active_segment();
        let Ok(contents) = std::fs::read(&path) else {
            return Ok(false);
        };
        if contents.is_empty() || contents.ends_with(b"\n") {
            return Ok(false);
        }

        let split = contents
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let (intact, damaged) = contents.split_at(split);

        let quarantine = self.directory.join(format!(
            "audit.quarantine.{}.jsonl",
            SystemTime::UNIX_EPOCH
                .elapsed()
                .map(|elapsed| elapsed.as_millis())
                .unwrap_or(0)
        ));
        std::fs::write(&quarantine, damaged).map_err(|_| SinkError::WriteFailed)?;
        std::fs::write(&path, intact).map_err(|_| SinkError::WriteFailed)?;
        Ok(true)
    }
}

/// An exclusive lock held for the duration of one append.
///
/// `create_new` is the primitive: it is atomic on every platform this targets,
/// which a check-then-create pair is not.
struct LockGuard {
    path: PathBuf,
}

impl LockGuard {
    fn acquire(directory: &Path) -> Result<Self, SinkError> {
        let path = directory.join(LOCK_FILE);
        let deadline = std::time::Instant::now() + LOCK_TIMEOUT;

        loop {
            match OpenOptions::new().create_new(true).write(true).open(&path) {
                Ok(file) => {
                    drop(file);
                    return Ok(Self { path });
                }
                Err(_) => {
                    if Self::is_stale(&path) {
                        // Best effort: if another process wins the race to
                        // remove it, this one simply retries.
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(SinkError::LockUnavailable);
                    }
                    std::thread::sleep(LOCK_POLL);
                }
            }
        }
    }

    fn is_stale(path: &Path) -> bool {
        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        let Ok(modified) = metadata.modified() else {
            return false;
        };
        modified.elapsed().is_ok_and(elapsed_is_stale)
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Best effort. A failure here leaves a lock that the staleness check
        // clears, which is why that check exists.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Reads every intact record in a segment. Diagnostics and tests only.
pub fn read_segment(path: &Path) -> Vec<String> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    contents
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ofw_contracts::{EnvironmentClass, Identifier};

    use crate::{
        AuditEvent, AuditHealth, AuditOutcome, Digest, EventType, Health, REDACTION_PROFILE_ID,
        REDACTION_PROFILE_VERSION, Redaction, SCHEMA_VERSION, Source,
    };

    use super::{
        ACTIVE_SEGMENT, AuditSink, LOCK_STALE_AFTER, MAX_RECORD_BYTES, MAX_SEGMENT_BYTES,
        SinkError, elapsed_is_stale, should_rotate,
    };

    /// Written numerically so no fixture in this module needs an escape.
    const NEWLINE: u8 = 10;

    fn directory(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ofw-sink-{}-{label}", std::process::id()));
        match std::fs::create_dir_all(&path) {
            Ok(()) => path,
            Err(error) => unreachable!("test directory must be creatable: {error}"),
        }
    }

    /// One complete record: a body and the newline that terminates it.
    fn record(body: &str) -> Vec<u8> {
        let mut bytes = body.as_bytes().to_vec();
        bytes.push(NEWLINE);
        bytes
    }

    fn sink_in(directory: &std::path::Path) -> AuditSink {
        match AuditSink::open(directory, None) {
            Ok(sink) => sink,
            Err(error) => unreachable!("the sink must open: {error}"),
        }
    }

    fn write(path: &std::path::Path, bytes: &[u8]) {
        match std::fs::write(path, bytes) {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
    }

    fn read(path: &std::path::Path) -> Vec<u8> {
        match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => unreachable!("test file must be readable: {error}"),
        }
    }

    /// The bounds are the sizes they are documented to be.
    ///
    /// Written as products (`8 * 1024 * 1024`), and a mutation run replaced the
    /// multiplication with addition in both. Nothing noticed, because nothing
    /// ever compared them to a number -- an 8 MiB segment bound silently
    /// becoming 1 033 bytes would have rotated on almost every append.
    #[test]
    fn the_documented_bounds_are_the_sizes_they_claim() {
        assert_eq!(MAX_SEGMENT_BYTES, 8_388_608);
        assert_eq!(MAX_RECORD_BYTES, 65_536);
        assert_eq!(LOCK_STALE_AFTER, Duration::from_secs(120));
    }

    /// Both halves of the rotation rule are load-bearing, and they differ.
    #[test]
    fn rotation_needs_a_non_empty_segment_and_an_overflowing_one() {
        // An empty segment never rotates, however large the line. Without this
        // half, the first append to a fresh sink closes an empty segment and a
        // reader cannot tell rotation from data loss.
        assert!(!should_rotate(0, MAX_RECORD_BYTES));
        assert!(!should_rotate(0, 1));

        // A non-empty segment rotates only once the line would take it past the
        // bound -- pinned at the boundary and one either side, because `==` and
        // `>=` mutations of the comparison each move it by exactly one.
        assert!(
            !should_rotate(MAX_SEGMENT_BYTES - 1, 1),
            "landing exactly on the bound is not past it"
        );
        assert!(should_rotate(MAX_SEGMENT_BYTES, 1), "one byte past");
        assert!(should_rotate(MAX_SEGMENT_BYTES - 1, 2), "two bytes past");
        assert!(!should_rotate(1, 1), "far under the bound");

        // Saturating rather than wrapping: a line that would overflow a u64
        // must rotate, not wrap to a small projection and skip rotation.
        assert!(should_rotate(u64::MAX, usize::MAX));
    }

    /// The staleness boundary is pinned on both sides.
    ///
    /// Breaking a lock too early lets two processes append at once; breaking it
    /// too late strands every later decision behind a dead process. Neither
    /// direction is safe, so the boundary is asserted rather than a direction.
    #[test]
    fn the_lock_staleness_boundary_holds_on_both_sides() {
        let timeout = LOCK_STALE_AFTER.as_secs();
        assert!(!elapsed_is_stale(Duration::from_secs(0)));
        assert!(!elapsed_is_stale(Duration::from_secs(timeout - 1)));
        assert!(
            !elapsed_is_stale(Duration::from_secs(timeout)),
            "a lock held for exactly the timeout is not yet stale"
        );
        assert!(elapsed_is_stale(Duration::from_secs(timeout + 1)));
        assert!(elapsed_is_stale(Duration::from_secs(timeout * 100)));
    }

    /// Rotation renames the active segment rather than reporting success.
    ///
    /// `rotate` returning `Ok(())` without moving anything survived every test,
    /// because rotation was only ever observed through `append`, which reports
    /// the same success either way. The evidence that matters is on disk.
    #[test]
    fn rotation_moves_the_active_segment_aside() {
        let directory = directory("rotate");
        let sink = sink_in(&directory);
        let active = directory.join(ACTIVE_SEGMENT);
        let closed = directory.join("audit.1.jsonl");
        let _ = std::fs::remove_file(&closed);
        let contents = record(r#"{"a":1}"#);
        write(&active, &contents);

        match sink.rotate(&active) {
            Ok(()) => {}
            Err(error) => unreachable!("rotation must succeed: {error}"),
        }
        assert!(!active.exists(), "the active segment was not moved");
        assert!(closed.exists(), "the closed segment was not created");
        assert_eq!(read(&closed), contents, "the records must survive intact");
    }

    /// Quarantine splits after the last complete record, not before it.
    ///
    /// The split index is `position_of_last_newline + 1`. Mutating that `+ 1`
    /// to `-` or `*` moves the boundary onto or past the newline, which either
    /// strands a newline at the head of the quarantine file or -- worse --
    /// leaves a partial record in the active segment while reporting the damage
    /// handled.
    #[test]
    fn quarantine_splits_after_the_last_complete_record() {
        let directory = directory("quarantine");
        let sink = sink_in(&directory);
        let active = directory.join(ACTIVE_SEGMENT);

        let intact = record(r#"{"intact":1}"#);
        let damaged = r#"{"trunc"#.as_bytes();
        let mut contents = intact.clone();
        contents.extend_from_slice(damaged);
        write(&active, &contents);

        match sink.quarantine_partial_record() {
            Ok(true) => {}
            other => unreachable!("a damaged trailing record must be quarantined: {other:?}"),
        }

        assert_eq!(
            read(&active),
            intact,
            "the intact record must survive whole, its newline included"
        );

        let quarantined: Vec<_> = match std::fs::read_dir(&directory) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("audit.quarantine."))
                })
                .collect(),
            Err(error) => unreachable!("the directory must be readable: {error}"),
        };
        assert_eq!(quarantined.len(), 1, "exactly one quarantine file");
        let Some(path) = quarantined.first() else {
            unreachable!("exactly one quarantine file")
        };
        assert_eq!(
            read(path),
            damaged,
            "the damaged bytes are kept exactly, with no newline taken from the intact record"
        );
    }

    /// Every sink error renders as distinct, non-empty text.
    #[test]
    fn every_sink_error_renders_a_distinct_message() {
        let all = [
            SinkError::DirectoryUnusable,
            SinkError::DirectoryInsideRepository,
            SinkError::LockUnavailable,
            SinkError::RecordTooLarge,
            SinkError::WriteFailed,
            SinkError::RotationFailed,
            SinkError::QuarantinedPriorRecord,
        ];
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for error in all {
            let rendered = match error {
                // Exhaustive: a variant added later stops compiling here.
                SinkError::DirectoryUnusable
                | SinkError::DirectoryInsideRepository
                | SinkError::LockUnavailable
                | SinkError::RecordTooLarge
                | SinkError::WriteFailed
                | SinkError::RotationFailed
                | SinkError::QuarantinedPriorRecord => error.to_string(),
            };
            assert!(!rendered.is_empty(), "{error:?} renders nothing");
            assert!(seen.insert(rendered), "{error:?} shares another message");
        }
        assert_eq!(seen.len(), all.len());
    }

    /// A minimal event whose serialized length can be tuned exactly.
    ///
    /// `occurred_at` is the pad: it is a plain ASCII `String`, so each added
    /// character adds exactly one byte to the JSON line and none of it needs
    /// escaping.
    fn event_padded_to(bytes: usize) -> AuditEvent {
        let identifier = match Identifier::new("turn-1") {
            Ok(value) => value,
            Err(error) => unreachable!("test identifier must be valid: {error}"),
        };
        let mut event = AuditEvent {
            schema_version: SCHEMA_VERSION,
            event_id: String::new(),
            occurred_at: String::new(),
            event_type: EventType::Evaluated,
            operation_id: None,
            decision_id: None,
            correlation_id: identifier,
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
                enforcement: AuditHealth::Unhealthy,
                audit: AuditHealth::Healthy,
                coverage: AuditHealth::Unhealthy,
            },
            redaction: Redaction {
                profile_id: REDACTION_PROFILE_ID,
                profile_version: REDACTION_PROFILE_VERSION,
                redacted_field_count: 0,
                canary_scan: "clean",
            },
        };
        let base = match event.to_json_line() {
            Ok(line) => line.len(),
            Err(error) => unreachable!("the fixture must serialize: {error}"),
        };
        assert!(base <= bytes, "the fixture is already larger than {bytes}");
        event.occurred_at = "0".repeat(bytes - base);
        event
    }

    /// The record-size bound is enforced at its boundary.
    ///
    /// A record too large to write is an audit failure, never a truncated
    /// record -- a truncated record is indistinguishable from a crash-damaged
    /// one, and the recovery path would quarantine it as damage. Nothing pinned
    /// the boundary, so two mutations of the comparison survived: `==` refuses
    /// only the single byte past the limit and admits everything larger, which
    /// is the shape that stops a bound being a bound.
    #[test]
    fn the_record_size_bound_holds_at_its_boundary() {
        let directory = directory("record-bound");
        let sink = sink_in(&directory);
        let active = directory.join(ACTIVE_SEGMENT);
        let _ = std::fs::remove_file(&active);

        let at_limit = event_padded_to(MAX_RECORD_BYTES);
        match at_limit.to_json_line() {
            Ok(line) => assert_eq!(line.len(), MAX_RECORD_BYTES, "the fixture is exact"),
            Err(error) => unreachable!("the fixture must serialize: {error}"),
        }
        match sink.append(&at_limit) {
            Ok(()) => {}
            Err(error) => unreachable!("a record of exactly the limit must append: {error}"),
        }

        // One over and far over: an `==` mutation refuses only the first.
        for excess in [1, 2, 1_024] {
            let over = event_padded_to(MAX_RECORD_BYTES + excess);
            assert_eq!(
                sink.append(&over),
                Err(SinkError::RecordTooLarge),
                "a record {excess} bytes over the limit must be refused"
            );
        }
    }
}
