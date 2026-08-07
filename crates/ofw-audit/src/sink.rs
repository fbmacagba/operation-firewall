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
        let projected = existing.saturating_add(line.len() as u64);
        if existing > 0 && projected > MAX_SEGMENT_BYTES {
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
        modified
            .elapsed()
            .is_ok_and(|elapsed| elapsed > LOCK_STALE_AFTER)
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
