#![forbid(unsafe_code)]

//! Target resolution: the facts about an operation that a command string
//! cannot supply.
//!
//! `ofw-intent` answers "what did this command *say*". This crate answers
//! "what does it actually touch, and where is that". Those are different
//! questions, and only the second one can establish containment: a path is
//! inside or outside a boundary because of what the filesystem says, never
//! because of how the string was spelled.
//!
//! # Nothing here trusts the agent
//!
//! The working directory and the repository boundary come from explicit
//! [`TrustedConfiguration`], never from the host envelope. A Codex envelope
//! carries a `cwd` field; resolving relative to it would let the caller choose
//! the boundary its own operation is measured against, which is the whole
//! control. The environment class is configuration for the same reason -- an
//! agent that could label its own environment `local` could unlock every
//! baseline row that requires a low-consequence environment.
//!
//! # What this slice does not do
//!
//! Platform-specific evidence -- reparse points, mount and volume identity,
//! alternate data streams, per-directory case sensitivity, Unicode
//! normalization -- is not collected. Canonicalization uses the platform's
//! native call through [`std::fs::canonicalize`], which does resolve symlinks
//! and junctions, so a link out of the boundary resolves out of the boundary.
//! It does not let this crate make the per-platform claims the design
//! ultimately requires, and nothing here assumes a platform default: anything
//! that cannot be established is an error, and an error is `indeterminate`.
//!
//! Resolution is also a point-in-time observation. The filesystem can change
//! between deciding and executing; binding a resolution to an approval and
//! revalidating immediately before execution is Milestone 2.

use std::path::{Path, PathBuf};

use ofw_contracts::{
    BlastRadius, Digest, EnvironmentClass, NamespacedName, OperationEffect, Reversibility, Version,
};
use ofw_core::{Containment, ResolvedContext, TargetCompleteness};
use ofw_intent::IntentCandidate;

/// Compiled maxima for one canonical path. Both are applied after
/// canonicalization, because canonicalization is what can grow a path:
/// a short relative spelling can resolve through links into a long deep one.
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_PATH_SEGMENTS: usize = 64;

/// Explicit operator-supplied configuration.
///
/// # Provenance
///
/// Two loaders exist. [`TrustedConfiguration::from_file`] reads a bounded file
/// and verifies its size, its structure and — on Unix — that it is not writable
/// by group or others. The CLI also accepts process environment variables,
/// which are explicit and outside the repository but carry no such checks.
///
/// Neither verifies **ownership**. That needs the effective uid on Unix and the
/// Win32 security API on Windows, and neither is reachable under this
/// workspace's `forbid(unsafe_code)` without a dependency taking the `unsafe`
/// on this crate's behalf. On Windows the permission check does not run either,
/// because `std` exposes only a read-only flag while the real answer is an ACL.
/// `ofw doctor` reports which loader supplied the configuration and what was
/// checked, rather than leaving a reader to assume the stronger answer.
///
/// The practical exposure today is nil rather than merely small: `environment`
/// only gates baseline rows that reach `allow`, and no operation in the
/// interpreted subset can reach `allow` at all. It becomes load-bearing the
/// moment a non-executing operation is interpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedConfiguration {
    working_directory: PathBuf,
    repository_boundary: PathBuf,
    environment: EnvironmentClass,
}

/// The largest trusted-configuration file this crate will read.
///
/// Trusted configuration is a handful of short lines. A bound here means an
/// enormous file is refused before it is read into memory rather than after.
pub const MAX_CONFIGURATION_BYTES: u64 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    WorkingDirectoryNotAbsolute,
    RepositoryBoundaryNotAbsolute,
    /// `EnvironmentClass::Unknown` is not configurable. Absent configuration
    /// must produce `indeterminate` through a missing configuration, not a
    /// successfully configured "unknown" that later reads as a decided fact.
    EnvironmentNotConfigurable,
    PathTooLong,
    NonUtf8Path,
    /// The file could not be opened, read, or stat'd.
    FileUnreadable,
    FileTooLarge,
    /// The file is writable by someone other than its owner.
    ///
    /// Refused rather than warned about: a configuration file anyone may write
    /// is not trusted configuration, and this file names the boundary every
    /// containment decision is measured against. Someone who can rewrite it can
    /// move the boundary around any operation they like.
    FileWritableByOthers,
    /// A line that is neither blank, a comment, nor `key = value`.
    FileMalformed,
    FileUnknownKey,
    FileDuplicateKey,
    FileMissingKey,
}

impl TrustedConfiguration {
    pub fn new(
        working_directory: PathBuf,
        repository_boundary: PathBuf,
        environment: EnvironmentClass,
    ) -> Result<Self, ConfigurationError> {
        if !working_directory.is_absolute() {
            return Err(ConfigurationError::WorkingDirectoryNotAbsolute);
        }
        if !repository_boundary.is_absolute() {
            return Err(ConfigurationError::RepositoryBoundaryNotAbsolute);
        }
        if matches!(environment, EnvironmentClass::Unknown) {
            return Err(ConfigurationError::EnvironmentNotConfigurable);
        }
        for path in [&working_directory, &repository_boundary] {
            match path.to_str() {
                None => return Err(ConfigurationError::NonUtf8Path),
                Some(text) if text.len() > MAX_PATH_BYTES => {
                    return Err(ConfigurationError::PathTooLong);
                }
                Some(_) => {}
            }
        }

        Ok(Self {
            working_directory,
            repository_boundary,
            environment,
        })
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn repository_boundary(&self) -> &Path {
        &self.repository_boundary
    }

    #[must_use]
    pub const fn environment(&self) -> EnvironmentClass {
        self.environment
    }

    /// Whether both configured paths canonicalize on this filesystem.
    ///
    /// For diagnostics only, and never consulted on the decision path: a
    /// decision must be made against the paths as they are at the moment of
    /// resolution, not against a probe that ran earlier.
    ///
    /// It exists because [`TrustedConfiguration::new`] validates shape and not
    /// existence, so a configuration containing a typo is well-formed. Without
    /// this, `ofw doctor` would report a typo as correctly configured while
    /// every assessment against it came out indeterminate.
    #[must_use]
    pub fn paths_resolvable(&self) -> bool {
        canonicalize(&self.working_directory).is_some()
            && canonicalize(&self.repository_boundary).is_some()
    }

    /// Loads trusted configuration from a file, verifying what can be verified.
    ///
    /// The design requires "a bounded configuration file whose ownership and
    /// permissions are verified at startup". This delivers the bound and the
    /// permission half; the ownership half is stated honestly below rather than
    /// implied by the function existing.
    ///
    /// Format is deliberately not JSON or TOML: `key = value`, one per line,
    /// `#` comments, every key required exactly once and no unknown key
    /// tolerated. A configuration file that silently ignores a key it does not
    /// understand is one where a typo in `repository_boundary` reads as an
    /// absent boundary, and this crate has no defaults to fall back on. Writing
    /// the parser by hand also keeps a serialization dependency out of the
    /// crate that decides containment.
    ///
    /// # What is verified, and what is not
    ///
    /// **Verified:** size, that every required key is present exactly once,
    /// that no unknown key appears, and — on Unix — that the file is not
    /// writable by group or others.
    ///
    /// **Not verified:** that the file is *owned* by the invoking user. That
    /// needs the effective uid on Unix and the Win32 security API on Windows,
    /// neither reachable under this workspace's `forbid(unsafe_code)` without a
    /// dependency carrying the `unsafe` on this crate's behalf. On Windows the
    /// permission check does not run at all, because `std` exposes only a
    /// read-only flag and the real answer lives in an ACL.
    ///
    /// So this is a genuine improvement on reading environment variables with
    /// no checks, and it is not the full requirement. `ofw doctor` reports the
    /// difference rather than leaving a reader to assume the stronger one.
    pub fn from_file(path: &Path) -> Result<Self, ConfigurationError> {
        let metadata = std::fs::metadata(path).map_err(|_| ConfigurationError::FileUnreadable)?;
        if metadata.len() > MAX_CONFIGURATION_BYTES {
            return Err(ConfigurationError::FileTooLarge);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !permissions_are_exclusive(metadata.permissions().mode()) {
                return Err(ConfigurationError::FileWritableByOthers);
            }
        }

        let contents =
            std::fs::read_to_string(path).map_err(|_| ConfigurationError::FileUnreadable)?;
        parse_configuration(&contents)
    }
}

/// Whether a Unix mode denies write to group and others.
///
/// Separated from the syscall so the rule itself is testable on every platform,
/// including the one where it cannot be applied. The alternative — asserting it
/// only inside `#[cfg(unix)]` — would leave the decision untested on two of the
/// three CI platforms while looking covered.
#[must_use]
pub const fn permissions_are_exclusive(mode: u32) -> bool {
    // 0o022 is group-write plus other-write. Read access is not checked: a
    // readable boundary path is not a secret, and refusing readable
    // configuration would push operators toward modes they do not understand.
    mode & 0o022 == 0
}

/// Parses the `key = value` body of a trusted-configuration file.
///
/// Public for tests on every platform; the file-reading half is what varies.
pub fn parse_configuration(contents: &str) -> Result<TrustedConfiguration, ConfigurationError> {
    let mut working_directory: Option<PathBuf> = None;
    let mut repository_boundary: Option<PathBuf> = None;
    let mut environment: Option<EnvironmentClass> = None;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigurationError::FileMalformed);
        };
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() || value.is_empty() {
            return Err(ConfigurationError::FileMalformed);
        }

        // Each arm refuses a second occurrence. Last-writer-wins would let a
        // line appended to the end of the file silently replace the boundary.
        match key {
            "working_directory" => {
                if working_directory.replace(PathBuf::from(value)).is_some() {
                    return Err(ConfigurationError::FileDuplicateKey);
                }
            }
            "repository_boundary" => {
                if repository_boundary.replace(PathBuf::from(value)).is_some() {
                    return Err(ConfigurationError::FileDuplicateKey);
                }
            }
            "environment" => {
                let class =
                    environment_from_label(value).ok_or(ConfigurationError::FileMalformed)?;
                if environment.replace(class).is_some() {
                    return Err(ConfigurationError::FileDuplicateKey);
                }
            }
            _ => return Err(ConfigurationError::FileUnknownKey),
        }
    }

    let (Some(working_directory), Some(repository_boundary), Some(environment)) =
        (working_directory, repository_boundary, environment)
    else {
        return Err(ConfigurationError::FileMissingKey);
    };

    // Every value still goes through the same constructor an in-process caller
    // uses, so a file cannot produce a configuration a caller could not.
    TrustedConfiguration::new(working_directory, repository_boundary, environment)
}

/// Maps a configuration label to an environment class.
///
/// `unknown` is deliberately absent. It is the value that means "nobody
/// established this", and accepting it as a label would let a configuration
/// assert the absence of knowledge as though it were knowledge.
#[must_use]
pub fn environment_from_label(label: &str) -> Option<EnvironmentClass> {
    match label {
        "local" => Some(EnvironmentClass::Local),
        "development" => Some(EnvironmentClass::Development),
        "test" => Some(EnvironmentClass::Test),
        "staging" => Some(EnvironmentClass::Staging),
        "production" => Some(EnvironmentClass::Production),
        "shared" => Some(EnvironmentClass::Shared),
        _ => None,
    }
}

/// Why an interpreted operation could not be resolved.
///
/// Every variant is `indeterminate` to the caller. None of them is a weaker
/// decision than the operation would otherwise have received: an operation
/// this crate cannot resolve has no proof, and no proof is never an allow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    /// The operation kind has no declared target scope in this slice.
    OperationKindUnsupported,
    /// The candidate carries path operands for a kind whose grammar accepts
    /// none. A contradiction between the two layers, and refusing is the only
    /// safe reading: whichever is wrong, resolving under either assumption
    /// produces a proof about targets that were not established.
    OperandsUnexpectedForKind,
    /// A path operand did not canonicalize.
    ///
    /// The whole operation fails rather than resolving the paths that did
    /// work. A partial list would understate what the command touches, and
    /// containment computed across it would describe a subset while reading as
    /// though it described the operation.
    PathOperandUnresolvable,
    /// The effect's reversibility is not derivable yet.
    EffectUnsupported,
    RepositoryBoundaryUnresolvable,
    WorkingDirectoryUnresolvable,
    NonUtf8Path,
    PathTooLong,
    TooManyPathSegments,
    /// A compiled-in target kind stopped satisfying the contract's name
    /// syntax. A build-time defect, but it must not degrade into a resolution
    /// that simply omits the kind it could not represent.
    TargetKindUnrepresentable,
    /// A creation names a path that is already there.
    ///
    /// The document says create; the filesystem says something is in the way.
    /// Applying it would overwrite, which is an update — so the effect the
    /// decision would be made under is not the effect that would occur, and
    /// `Create` is the one effect this crate calls cleanly reversible. Refused
    /// rather than resolved under either reading, exactly as a kind arriving
    /// with operands its grammar forbids is refused.
    CreationTargetExists,
}

impl core::fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::OperationKindUnsupported => "operation kind has no declared target scope",
            Self::OperandsUnexpectedForKind => {
                "operation kind accepts no operands but the candidate carries some"
            }
            Self::PathOperandUnresolvable => "a path operand could not be canonicalized",
            Self::EffectUnsupported => "operation effect has no derivable reversibility",
            Self::RepositoryBoundaryUnresolvable => {
                "repository boundary could not be canonicalized"
            }
            Self::WorkingDirectoryUnresolvable => "working directory could not be canonicalized",
            Self::NonUtf8Path => "canonical path is not valid UTF-8",
            Self::PathTooLong => "canonical path exceeds the configured byte limit",
            Self::TooManyPathSegments => "canonical path exceeds the configured segment limit",
            Self::TargetKindUnrepresentable => "target kind is not a representable contract name",
            Self::CreationTargetExists => "a creation target already exists",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ResolutionError {}

/// What an operation's targets are.
///
/// Keyed on the operation kind. See [`target_scope`] for why that matters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetScope {
    /// The whole repository working tree, addressed through the trusted
    /// working directory.
    Repository,
    /// A specific list of paths, each resolved against the trusted working
    /// directory. Every one must already exist.
    Paths,
    /// A specific list of paths the operation would *write*, where a target
    /// need not exist yet.
    ///
    /// Separate from [`Paths`](Self::Paths) because the two answer "this did
    /// not canonicalize" differently, and conflating them would be a bypass in
    /// either direction. A read of a path that is not there resolves nothing
    /// and must fail. A write to a path that is not there is the ordinary case
    /// — refusing it would make every file creation indeterminate — so the
    /// design's rule applies instead: canonicalize the nearest existing
    /// ancestor and append the remaining components without claiming they
    /// exist.
    WritePaths,
}

/// The contract name for a whole repository working tree as a target.
const REPOSITORY_TARGET_KIND: &str = "git.repository";

/// The contract name for one named path inside a working tree.
const PATH_TARGET_KIND: &str = "git.worktree_path";

/// The revalidation contract revision this crate emits.
pub const FINGERPRINT_SCHEMA_VERSION: &str = "1.0";

/// A bounded identity for exactly what a decision was made about.
///
/// Milestone 2 binds an approval to one of these and recomputes it immediately
/// before execution; this milestone produces it and compares it. The property
/// it exists to provide is that **any change to what the operation would touch
/// yields a different fingerprint**, so an approval granted for one target set
/// cannot be redeemed against another.
///
/// It carries digests rather than paths for the same reason an audit record
/// does: a fingerprint may be stored, logged or handed to another process, and
/// none of those should distribute the filesystem layout of the repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevalidationFingerprint {
    schema_version: &'static str,
    operation_kind: NamespacedName,
    grammar_revision: Version,
    repository_boundary: Digest,
    target_count: usize,
    target_set: Digest,
}

impl RevalidationFingerprint {
    #[must_use]
    pub fn operation_kind(&self) -> &NamespacedName {
        &self.operation_kind
    }

    #[must_use]
    pub const fn target_count(&self) -> usize {
        self.target_count
    }

    #[must_use]
    pub const fn target_set(&self) -> &Digest {
        &self.target_set
    }

    /// A single digest over the whole fingerprint.
    ///
    /// What Milestone 2 binds an approval to. Built with the same
    /// length-prefixed framing as the target set, so no two distinct
    /// fingerprints can produce one value.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut framed = Vec::new();
        for field in [
            self.schema_version,
            self.operation_kind.as_str(),
            self.grammar_revision.as_str(),
            self.repository_boundary.value(),
        ] {
            frame(&mut framed, field.as_bytes());
        }
        frame(&mut framed, &self.target_count.to_le_bytes());
        frame(&mut framed, self.target_set.value().as_bytes());
        Digest::of(&framed)
    }
}

/// What differs between two fingerprints, if anything.
///
/// Reported rather than collapsed to a boolean because the answers mean
/// different things to an operator: a changed target set is the filesystem
/// moving under a decision, while a changed grammar revision means the decision
/// was made by a different interpreter than the one about to act on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintChange {
    SchemaVersion,
    OperationKind,
    GrammarRevision,
    RepositoryBoundary,
    TargetCount,
    TargetSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revalidation {
    Unchanged,
    Changed(FingerprintChange),
}

/// Compares a recorded fingerprint against one computed now.
///
/// Every field is compared. `Unchanged` is returned only when all of them
/// match, so adding a field to [`RevalidationFingerprint`] without adding it
/// here would be a silent weakening — which is why the struct is destructured
/// rather than field-accessed: a new field makes this function stop compiling.
#[must_use]
pub fn revalidate(
    recorded: &RevalidationFingerprint,
    current: &RevalidationFingerprint,
) -> Revalidation {
    let RevalidationFingerprint {
        schema_version,
        operation_kind,
        grammar_revision,
        repository_boundary,
        target_count,
        target_set,
    } = recorded;

    if *schema_version != current.schema_version {
        return Revalidation::Changed(FingerprintChange::SchemaVersion);
    }
    if *operation_kind != current.operation_kind {
        return Revalidation::Changed(FingerprintChange::OperationKind);
    }
    if *grammar_revision != current.grammar_revision {
        return Revalidation::Changed(FingerprintChange::GrammarRevision);
    }
    if *repository_boundary != current.repository_boundary {
        return Revalidation::Changed(FingerprintChange::RepositoryBoundary);
    }
    // Checked before the set digest so a target appearing twice is reported as
    // a count change rather than as an opaque set change.
    if *target_count != current.target_count {
        return Revalidation::Changed(FingerprintChange::TargetCount);
    }
    if *target_set != current.target_set {
        return Revalidation::Changed(FingerprintChange::TargetSet);
    }
    Revalidation::Unchanged
}

/// Appends one length-prefixed field to a digest input.
///
/// The framing is the whole point. Joining variable-length values with a
/// separator is ambiguous whenever a value may contain the separator, and a
/// filesystem path may contain almost anything — a newline is a legal filename
/// character on Unix. Under newline joining the two-target sets
/// `["a\nb", "c"]` and `["a", "b\nc"]` produce identical bytes *and* identical
/// counts, so an approval for one would revalidate against the other.
/// `red_first_witness_detects_ambiguous_target_framing` retains that collision.
fn frame(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u64).to_le_bytes());
    output.extend_from_slice(field);
}

/// One resolved operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTargets {
    context: ResolvedContext,
    canonical_targets: Vec<String>,
    canonical_boundary: String,
    target_kinds: Vec<NamespacedName>,
}

impl ResolvedTargets {
    #[must_use]
    pub const fn context(&self) -> &ResolvedContext {
        &self.context
    }

    /// The canonical identities the decision was made about.
    ///
    /// Milestone 2 turns these into the revalidation fingerprint that an
    /// approval is bound to; this slice only produces them.
    #[must_use]
    pub fn canonical_targets(&self) -> &[String] {
        &self.canonical_targets
    }

    /// What kind of thing was resolved, for policy target selectors.
    ///
    /// Derived from the resolved scope rather than from the command, so a
    /// policy rule selecting on a target kind is selecting on what the
    /// resolver found and not on what the agent wrote.
    #[must_use]
    pub fn target_kinds(&self) -> &[NamespacedName] {
        &self.target_kinds
    }

    /// Builds the revalidation fingerprint for this resolution.
    ///
    /// The target set is **sorted** before framing, so the fingerprint is a
    /// property of which paths are involved and not of the order the operand
    /// list happened to arrive in. Reordering the same pathspecs is genuinely
    /// not a change, and treating it as one would make revalidation fail for a
    /// reason no operator could act on. Duplicates survive sorting and are
    /// counted, so `[a, a]` and `[a]` stay distinct.
    #[must_use]
    pub fn fingerprint(
        &self,
        operation_kind: &NamespacedName,
        grammar_revision: &Version,
    ) -> RevalidationFingerprint {
        let mut sorted: Vec<&String> = self.canonical_targets.iter().collect();
        sorted.sort();

        let mut framed = Vec::new();
        for target in &sorted {
            frame(&mut framed, target.as_bytes());
        }

        RevalidationFingerprint {
            schema_version: FINGERPRINT_SCHEMA_VERSION,
            operation_kind: operation_kind.clone(),
            grammar_revision: grammar_revision.clone(),
            repository_boundary: Digest::of(self.canonical_boundary.as_bytes()),
            target_count: self.canonical_targets.len(),
            target_set: Digest::of(&framed),
        }
    }
}

/// Establishes the resolver-supplied facts for one interpreted operation.
pub fn resolve(
    candidate: &IntentCandidate,
    configuration: &TrustedConfiguration,
) -> Result<ResolvedTargets, ResolutionError> {
    let scope = target_scope(
        candidate.operation_kind().as_str(),
        candidate.path_candidates().len(),
    )?;

    // Reversibility is derived from the effect, never accepted from anywhere.
    // Each arm is argued for in the slice that introduces it; the rest stay
    // unsupported rather than being given a plausible-looking answer.
    let reversibility = match candidate.effect() {
        OperationEffect::Read => Reversibility::Reversible,
        // A creation loses nothing: undoing it is deleting what was created,
        // and nothing prior was overwritten. That last clause is a real
        // precondition rather than a turn of phrase, which is why the write
        // scope below refuses a creation whose target already exists — an
        // "add" over an existing file is an overwrite wearing a create's name,
        // and this arm would call the overwrite reversible.
        OperationEffect::Create => Reversibility::Reversible,
        // Overwriting, removing and renaming all destroy something. Whether it
        // comes back depends on whether it was committed, and this crate
        // deliberately does not read `.git` or invoke git, so it cannot know.
        // `ConditionallyRecoverable` states the category without asserting the
        // condition holds; `Reversible` would assert it, and `Unknown` would
        // discard what we do know. None of the three reaches the allow row.
        OperationEffect::Update | OperationEffect::Delete | OperationEffect::Move => {
            Reversibility::ConditionallyRecoverable
        }
        OperationEffect::Execute
        | OperationEffect::PermissionChange
        | OperationEffect::Publish
        | OperationEffect::UnknownMutation => return Err(ResolutionError::EffectUnsupported),
    };

    let boundary = canonicalize(&configuration.repository_boundary)
        .ok_or(ResolutionError::RepositoryBoundaryUnresolvable)?;

    let (targets, target_kinds, blast_radius) = match scope {
        TargetScope::Repository => {
            let working = canonicalize(&configuration.working_directory)
                .ok_or(ResolutionError::WorkingDirectoryUnresolvable)?;
            let kind = NamespacedName::new(REPOSITORY_TARGET_KIND)
                .map_err(|_| ResolutionError::TargetKindUnrepresentable)?;
            // One repository working tree: bounded, not single. A repository
            // read observes every tracked path under it.
            (vec![working], vec![kind], BlastRadius::Bounded)
        }
        TargetScope::Paths => {
            let working = canonicalize(&configuration.working_directory)
                .ok_or(ResolutionError::WorkingDirectoryUnresolvable)?;
            let kind = NamespacedName::new(PATH_TARGET_KIND)
                .map_err(|_| ResolutionError::TargetKindUnrepresentable)?;

            let mut resolved = Vec::with_capacity(candidate.path_candidates().len());
            for operand in candidate.path_candidates() {
                // Joined against the *trusted* working directory, never the
                // envelope's. An absolute operand replaces the base entirely
                // here, on every platform -- which is intended, because the
                // result is then canonicalized and measured against the
                // boundary like any other path. Escape is caught by
                // containment, not by refusing to join.
                let joined = working.join(operand);
                let canonical =
                    canonicalize(&joined).ok_or(ResolutionError::PathOperandUnresolvable)?;
                resolved.push(canonical);
            }

            // Bounded rather than single even for one operand: a pathspec
            // names a directory as readily as a file, and telling those apart
            // needs a metadata call whose answer can change between deciding
            // and executing. The narrower fact lives in `canonical_targets`
            // and in the target kind, where it is exact.
            (resolved, vec![kind], BlastRadius::Bounded)
        }
        TargetScope::WritePaths => {
            let working = canonicalize(&configuration.working_directory)
                .ok_or(ResolutionError::WorkingDirectoryUnresolvable)?;
            let kind = NamespacedName::new(PATH_TARGET_KIND)
                .map_err(|_| ResolutionError::TargetKindUnrepresentable)?;

            // A document whose most consequential operation is a create
            // contains *only* creates: create is the least consequential of the
            // four, so it can only be the maximum when nothing outranks it.
            // That is what makes this check sound for the whole target list
            // rather than needing per-path expectations.
            let creation_only = matches!(candidate.effect(), OperationEffect::Create);

            let mut resolved = Vec::with_capacity(candidate.path_candidates().len());
            for operand in candidate.path_candidates() {
                if creation_only && canonicalize(&working.join(operand)).is_some() {
                    return Err(ResolutionError::CreationTargetExists);
                }
                resolved.push(resolve_write_path(&working, operand)?);
            }

            (resolved, vec![kind], BlastRadius::Bounded)
        }
    };

    let mut canonical_targets = Vec::with_capacity(targets.len());
    for target in &targets {
        canonical_targets.push(bounded_utf8(target)?);
    }

    // Containment is decided on canonical paths, compared by path component.
    // Both halves matter and each has a retained witness: comparing the
    // configured spelling instead of the canonical one is defeated by
    // traversal and by symlinks, and comparing canonical paths as strings
    // instead of as components is defeated by a sibling whose name merely
    // starts with the boundary's.
    let containment = if targets.iter().all(|target| target.starts_with(&boundary)) {
        Containment::RepositoryLocal
    } else {
        Containment::CrossBoundary
    };

    // Complete because every target for this scope was canonicalized -- a
    // failure to canonicalize returned above rather than reaching here. This
    // field only starts discriminating between inputs when path operands are
    // resolved and a subset of them can fail, which is why there is no
    // red-first witness for it: today there is no input that produces
    // `Incomplete`, so a test claiming to detect its loss would be testing
    // nothing.
    let target_completeness = TargetCompleteness::Complete;

    let canonical_boundary = bounded_utf8(&boundary)?;

    Ok(ResolvedTargets {
        context: ResolvedContext {
            containment,
            target_completeness,
            environment: configuration.environment,
            blast_radius,
            reversibility,
        },
        canonical_targets,
        canonical_boundary,
        target_kinds,
    })
}

/// What the operation's targets are, from the kind *and* the operand count.
///
/// Both arguments are load-bearing, and the reason is the danger this function
/// was written to avoid in the first place. Until `git log` and `git diff`
/// landed, no interpreted subcommand took operands, so "the kind" and "nothing
/// was extracted" gave the same answer everywhere and keying on the kind alone
/// was safe. That is no longer true: `git log` legitimately means the whole
/// repository with no operands and specific paths with them, so the count has
/// to be read.
///
/// Reading the count is exactly what makes a dropped-operand bug dangerous —
/// `git log -- src/x` whose extraction returned nothing becomes
/// indistinguishable from `git log`, and resolves the entire working tree as a
/// complete, repository-local target. That cannot be defended here, because
/// both layers agree; it is defended in the grammar, by
/// `pathspecs_are_extracted_only_after_the_separator`, and demonstrated
/// end-to-end by `red_first_witness_detects_dropped_pathspecs`.
///
/// What this function *can* defend is the contradiction: a kind whose grammar
/// accepts no operands arriving with some. That is refused rather than
/// resolved under either layer's assumption.
fn target_scope(
    operation_kind: &str,
    path_operands: usize,
) -> Result<TargetScope, ResolutionError> {
    match (operation_kind, path_operands) {
        ("git.status" | "git.rev_parse", 0) => Ok(TargetScope::Repository),
        ("git.status" | "git.rev_parse", _) => Err(ResolutionError::OperandsUnexpectedForKind),
        ("git.log" | "git.diff", 0) => Ok(TargetScope::Repository),
        ("git.log" | "git.diff", _) => Ok(TargetScope::Paths),
        // A patch that names no path is the same contradiction as a `git
        // status` that names one: the grammar cannot produce it, so the two
        // layers disagree, and resolving under either reading describes an
        // operation that is not happening.
        ("patch.add_file" | "patch.update_file" | "patch.delete_file" | "patch.move_file", 0) => {
            Err(ResolutionError::OperandsUnexpectedForKind)
        }
        ("patch.add_file" | "patch.update_file" | "patch.delete_file" | "patch.move_file", _) => {
            Ok(TargetScope::WritePaths)
        }
        _ => Err(ResolutionError::OperationKindUnsupported),
    }
}

/// Resolves a path the operation would write, which need not exist yet.
///
/// The design's rule: canonicalize the nearest existing ancestor and append the
/// remaining components without claiming they exist. Containment is then
/// decided on the result exactly as it is for a read.
///
/// # Why the appended part is safe to append
///
/// Nothing canonicalizes it, so a `..` inside it would survive into the
/// containment comparison as text and walk back out of the boundary. That is
/// why the patch grammar refuses `.` and `..` components lexically — the one
/// place in this project where traversal is a grammar concern rather than a
/// resolver one. This function depends on that and says so, rather than
/// re-deriving it from a path it has already lost the spelling of.
///
/// The ancestor walk stops at the first component that exists, so a symlinked
/// ancestor is still canonicalized and still measured. Only components that do
/// not exist are taken on trust, and a component that does not exist cannot be
/// a link to anywhere.
fn resolve_write_path(working: &Path, operand: &str) -> Result<PathBuf, ResolutionError> {
    let joined = working.join(operand);
    if let Some(canonical) = canonicalize(&joined) {
        return Ok(canonical);
    }

    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut ancestor = joined.as_path();
    loop {
        let (Some(parent), Some(name)) = (ancestor.parent(), ancestor.file_name()) else {
            // Ran out of ancestors without finding one that exists. The whole
            // chain is unresolvable, which for a write means the operand does
            // not name a place inside anything this process can see.
            return Err(ResolutionError::PathOperandUnresolvable);
        };
        missing.push(name.to_owned());
        if let Some(canonical) = canonicalize(parent) {
            let mut resolved = canonical;
            // Pushed back in the order they were stripped.
            for component in missing.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        if missing.len() > MAX_PATH_SEGMENTS {
            return Err(ResolutionError::TooManyPathSegments);
        }
        ancestor = parent;
    }
}

/// Canonicalizes through the platform's native call, or reports nothing.
///
/// A path that does not exist does not canonicalize, and that is the correct
/// answer for this slice: every interpreted operation reads something that is
/// already there. Creation targets need the design's "canonicalize the nearest
/// existing parent" rule, which belongs with the first interpreted creation.
fn canonicalize(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

fn bounded_utf8(path: &Path) -> Result<String, ResolutionError> {
    let text = path.to_str().ok_or(ResolutionError::NonUtf8Path)?;
    if text.len() > MAX_PATH_BYTES {
        return Err(ResolutionError::PathTooLong);
    }
    if path.components().count() > MAX_PATH_SEGMENTS {
        return Err(ResolutionError::TooManyPathSegments);
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use ofw_contracts::{BlastRadius, EnvironmentClass, NamespacedName, Reversibility, Version};
    use ofw_core::{
        BaselineRestriction, Containment, ExecutionSurface, SupportedOperationProof,
        TargetCompleteness, evidence_from_intent,
    };
    use ofw_intent::{Classification, IntentCandidate};

    use super::{
        ConfigurationError, Digest, FingerprintChange, MAX_CONFIGURATION_BYTES, MAX_PATH_BYTES,
        MAX_PATH_SEGMENTS, ResolutionError, Revalidation, RevalidationFingerprint, TargetScope,
        TrustedConfiguration, bounded_utf8, environment_from_label, frame, parse_configuration,
        permissions_are_exclusive, resolve, revalidate, target_scope,
    };

    /// Creates a real directory under the system temporary directory.
    ///
    /// Real directories rather than synthetic paths because canonicalization
    /// is the property under test, and canonicalization only happens to paths
    /// that exist.
    fn directory(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ofw-resolve-{}-{label}", std::process::id()));
        match std::fs::create_dir_all(&path) {
            Ok(()) => path,
            Err(error) => unreachable!("test directory must be creatable: {error}"),
        }
    }

    fn git_status() -> IntentCandidate {
        supported("git status")
    }

    /// Builds a patch candidate from directive lines, wrapping the terminators.
    fn patch(lines: &[&str]) -> IntentCandidate {
        let mut document = String::from("*** Begin Patch\n");
        for line in lines {
            document.push_str(line);
            document.push('\n');
        }
        document.push_str("*** End Patch\n");
        match ofw_intent::interpret_patch(&document) {
            ofw_intent::PatchClassification::Supported(candidate) => *candidate,
            other => unreachable!("{lines:?} must classify, got {other:?}"),
        }
    }

    fn supported(command: &str) -> IntentCandidate {
        match ofw_intent::interpret(command) {
            Ok(Classification::Supported(candidate)) => *candidate,
            other => unreachable!("{command} must classify, got {other:?}"),
        }
    }

    fn configuration(working: PathBuf, boundary: PathBuf) -> TrustedConfiguration {
        match TrustedConfiguration::new(working, boundary, EnvironmentClass::Local) {
            Ok(configuration) => configuration,
            Err(error) => unreachable!("test configuration must be valid: {error:?}"),
        }
    }

    fn resolved(configuration: &TrustedConfiguration) -> super::ResolvedTargets {
        match resolve(&git_status(), configuration) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("test operation must resolve: {error}"),
        }
    }

    #[test]
    fn a_repository_read_resolves_inside_its_boundary() {
        let boundary = directory("inside-boundary");
        let working = directory("inside-boundary/worktree");
        let resolved = resolved(&configuration(working, boundary.clone()));

        assert_eq!(resolved.context().containment, Containment::RepositoryLocal);
        assert_eq!(
            resolved.context().target_completeness,
            TargetCompleteness::Complete
        );
        assert_eq!(resolved.context().blast_radius, BlastRadius::Bounded);
        assert_eq!(resolved.context().reversibility, Reversibility::Reversible);
        assert_eq!(resolved.context().environment, EnvironmentClass::Local);
        assert_eq!(resolved.canonical_targets().len(), 1);
        assert_eq!(
            resolved
                .target_kinds()
                .iter()
                .map(NamespacedName::as_str)
                .collect::<Vec<_>>(),
            vec!["git.repository"]
        );
    }

    /// The payoff: a resolver fact reaching the decision.
    ///
    /// A contained repository read is `ask` rather than `allow` -- git carries
    /// an execution surface no argv can rule out -- and moving the working
    /// directory outside the boundary turns the same command into a baseline
    /// `deny`. Nothing about the command string changed.
    #[test]
    fn containment_decides_the_baseline_for_an_identical_command() {
        let inside = configuration(directory("decides/worktree"), directory("decides"));
        let outside = configuration(directory("outside-worktree"), directory("outside-boundary"));

        assert_eq!(baseline(&inside), BaselineRestriction::Ask);
        assert_eq!(baseline(&outside), BaselineRestriction::Deny);
    }

    fn baseline(configuration: &TrustedConfiguration) -> BaselineRestriction {
        let candidate = git_status();
        let context = *resolved(configuration).context();
        let version = match Version::new("1.0.0") {
            Ok(version) => version,
            Err(error) => unreachable!("test version must be valid: {error}"),
        };
        let evidence = evidence_from_intent(&candidate, &context, version);
        // Pinned here because it is the reason the contained case is `ask`:
        // if this ever became `None`, a contained repository read would reach
        // the bounded-read allow row.
        assert_eq!(evidence.execution_surface, ExecutionSurface::Present);
        match SupportedOperationProof::new(evidence) {
            Ok(proof) => proof.baseline(),
            Err(error) => unreachable!("resolved evidence must be provable: {error}"),
        }
    }

    #[test]
    fn red_first_witness_detects_string_prefix_containment() {
        // A sibling directory whose name merely begins with the boundary's.
        let boundary = directory("prefix");
        let working = directory("prefix-evil");
        let configuration = configuration(working, boundary);

        assert_eq!(
            resolved(&configuration).context().containment,
            Containment::CrossBoundary
        );
        // The retained witness compares the same canonical paths as strings,
        // and reads the sibling as living inside the boundary.
        assert_eq!(
            vulnerable_string_prefix_containment(&configuration),
            Containment::RepositoryLocal
        );
    }

    #[test]
    fn red_first_witness_detects_lexical_containment() {
        let boundary = directory("lexical");
        let escaped = directory("lexical-escaped");
        // Spelled so that it lexically begins with the boundary, while
        // resolving to a sibling of it.
        let mut traversal = boundary.clone();
        traversal.push("..");
        match escaped.file_name() {
            Some(name) => traversal.push(name),
            None => unreachable!("test directory must have a file name"),
        }
        let configuration = configuration(traversal, boundary);

        assert_eq!(
            resolved(&configuration).context().containment,
            Containment::CrossBoundary
        );
        // The retained witness checks the configured spelling instead of the
        // canonical path, and a traversal segment walks straight past it.
        assert_eq!(
            vulnerable_lexical_containment(&configuration),
            Containment::RepositoryLocal
        );
    }

    /// The danger the old scope witness guarded, now reachable for real.
    ///
    /// Before `git log` was interpreted this could only be shown against a
    /// synthetic helper, because no interpreted subcommand took operands. It
    /// is now a property of two real commands: dropping the operands of
    /// `git log -- <file>` turns it into `git log`, which is a legitimate
    /// whole-repository read. Nothing downstream can tell them apart -- both
    /// are complete, both are repository-local, both are provable -- so the
    /// resolved target silently widens from one file to the entire tree.
    ///
    /// This is why extraction is pinned in the grammar rather than inferred
    /// from a count anywhere below it.
    #[test]
    fn red_first_witness_detects_dropped_pathspecs() {
        let boundary = directory("dropped");
        let working = directory("dropped/worktree");
        let file = working.join("tracked.txt");
        match std::fs::write(&file, b"contents") {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
        let configuration = configuration(working.clone(), boundary);

        let scoped = match resolve(&supported("git log -- tracked.txt"), &configuration) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("a scoped log must resolve: {error}"),
        };
        assert_eq!(
            scoped
                .target_kinds()
                .iter()
                .map(NamespacedName::as_str)
                .collect::<Vec<_>>(),
            vec!["git.worktree_path"]
        );
        assert_eq!(scoped.canonical_targets().len(), 1);
        let Some(scoped_target) = scoped.canonical_targets().first() else {
            unreachable!("a scoped log must resolve one target")
        };
        assert!(scoped_target.ends_with("tracked.txt"));

        // The same command with its operands dropped. Indistinguishable from
        // an unscoped `git log`, and the target is now the whole working tree.
        let widened = match resolve(&supported("git log"), &configuration) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("an unscoped log must resolve: {error}"),
        };
        assert_eq!(
            widened
                .target_kinds()
                .iter()
                .map(NamespacedName::as_str)
                .collect::<Vec<_>>(),
            vec!["git.repository"]
        );
        let Some(widened_target) = widened.canonical_targets().first() else {
            unreachable!("an unscoped log must resolve one target")
        };
        assert!(!widened_target.ends_with("tracked.txt"));
        // Both are fully proven resolutions. Nothing about the widened one
        // looks degraded, which is precisely the problem.
        assert_eq!(
            widened.context().target_completeness,
            TargetCompleteness::Complete
        );
        assert_eq!(widened.context().containment, Containment::RepositoryLocal);
    }

    /// A kind whose grammar takes no operands must not resolve as a whole
    /// repository when it somehow arrives carrying some.
    #[test]
    fn red_first_witness_detects_scope_ignoring_unexpected_operands() {
        assert_eq!(
            target_scope("git.status", 0),
            Ok(TargetScope::Repository),
            "the ordinary case is unaffected"
        );
        assert_eq!(
            target_scope("git.status", 3),
            Err(ResolutionError::OperandsUnexpectedForKind)
        );
        // `git log` reads the count rather than refusing it, so the two kinds
        // are genuinely different and the arm is not dead.
        assert_eq!(target_scope("git.log", 0), Ok(TargetScope::Repository));
        assert_eq!(target_scope("git.log", 3), Ok(TargetScope::Paths));
        assert_eq!(
            target_scope("git.push", 0),
            Err(ResolutionError::OperationKindUnsupported)
        );

        // The retained witness keys on the kind alone. It reports a whole
        // repository for a status carrying operands it cannot have, and
        // collapses a path-scoped log into a repository read as well -- the
        // same widening, from two different directions.
        assert_eq!(
            vulnerable_scope_ignores_operand_count("git.status", 3),
            Some(TargetScope::Repository)
        );
        assert_eq!(
            vulnerable_scope_ignores_operand_count("git.log", 3),
            Some(TargetScope::Repository)
        );
    }

    /// A pathspec resolving outside the boundary is caught by containment, not
    /// by refusing traversal syntax.
    #[test]
    fn a_pathspec_escaping_the_boundary_is_cross_boundary() {
        let boundary = directory("escape");
        let working = directory("escape/worktree");
        let outside = directory("escape-outside");
        let secret = outside.join("secret.txt");
        match std::fs::write(&secret, b"secret") {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
        let configuration = configuration(working, boundary);

        // Spelled as a traversal, which the grammar deliberately passes
        // through. Canonicalization is what discovers where it lands.
        let command = format!(
            "git log -- ../../{}/secret.txt",
            match outside.file_name() {
                Some(name) => name.to_string_lossy().into_owned(),
                None => unreachable!("test directory must have a file name"),
            }
        );
        let resolved = match resolve(&supported(&command), &configuration) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("the escaping path must resolve: {error}"),
        };
        assert_eq!(resolved.context().containment, Containment::CrossBoundary);
    }

    /// A pathspec that names nothing fails the whole resolution.
    #[test]
    fn an_unresolvable_pathspec_fails_the_whole_operation() {
        let boundary = directory("absent-operand");
        let working = directory("absent-operand/worktree");
        let present = working.join("present.txt");
        match std::fs::write(&present, b"here") {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
        let configuration = configuration(working, boundary);

        // One good operand and one that names nothing. Resolving the good one
        // alone would report a complete resolution covering half the command.
        assert_eq!(
            resolve(
                &supported("git log -- present.txt no-such-file.txt"),
                &configuration
            ),
            Err(ResolutionError::PathOperandUnresolvable)
        );
    }

    #[test]
    fn an_unresolvable_boundary_is_an_error_rather_than_a_permissive_default() {
        let mut absent = directory("absent-boundary");
        absent.push("no-such-directory");
        let configuration = configuration(directory("absent-working"), absent);

        assert_eq!(
            resolve(&git_status(), &configuration),
            Err(ResolutionError::RepositoryBoundaryUnresolvable)
        );
    }

    #[test]
    fn configuration_rejects_what_it_cannot_trust() {
        let absolute = directory("configuration");
        assert_eq!(
            TrustedConfiguration::new(
                PathBuf::from("relative/path"),
                absolute.clone(),
                EnvironmentClass::Local
            ),
            Err(ConfigurationError::WorkingDirectoryNotAbsolute)
        );
        assert_eq!(
            TrustedConfiguration::new(
                absolute.clone(),
                PathBuf::from("relative/path"),
                EnvironmentClass::Local
            ),
            Err(ConfigurationError::RepositoryBoundaryNotAbsolute)
        );
        // "Unknown" is the value that means nobody established the
        // environment. It must arrive by absence, never by configuration.
        assert_eq!(
            TrustedConfiguration::new(absolute.clone(), absolute, EnvironmentClass::Unknown),
            Err(ConfigurationError::EnvironmentNotConfigurable)
        );
        assert_eq!(environment_from_label("unknown"), None);
        assert_eq!(environment_from_label("Local"), None);
        assert_eq!(
            environment_from_label("production"),
            Some(EnvironmentClass::Production)
        );
    }

    /// Every documented environment label maps to its own class, and nothing
    /// else maps at all.
    ///
    /// Three of the six arms were covered before a mutation run showed that
    /// deleting `development`, `staging` or `shared` changed nothing any test
    /// could see. A deleted arm falls through to `None`, so a configuration
    /// naming that environment is refused -- fail-closed, and a silent loss of
    /// a documented label rather than a bypass. Refusing to load is still the
    /// wrong answer for a label the documentation promises.
    #[test]
    fn every_environment_label_maps_to_its_own_class() {
        let labels = [
            ("local", EnvironmentClass::Local),
            ("development", EnvironmentClass::Development),
            ("test", EnvironmentClass::Test),
            ("staging", EnvironmentClass::Staging),
            ("production", EnvironmentClass::Production),
            ("shared", EnvironmentClass::Shared),
        ];

        let mut seen: std::collections::BTreeSet<EnvironmentClass> =
            std::collections::BTreeSet::new();
        for (label, class) in labels {
            assert_eq!(environment_from_label(label), Some(class), "label {label}");
            assert!(seen.insert(class), "two labels map to {class:?}");
            match class {
                // Exhaustive on purpose. A class added later stops compiling
                // here until it is given a label above -- except `Unknown`,
                // which must never acquire one.
                EnvironmentClass::Local
                | EnvironmentClass::Development
                | EnvironmentClass::Test
                | EnvironmentClass::Staging
                | EnvironmentClass::Production
                | EnvironmentClass::Shared => {}
                EnvironmentClass::Unknown => {
                    unreachable!("`unknown` means nobody established this; it is not a label")
                }
            }
        }

        for label in [
            "unknown",
            "Local",
            "",
            " local",
            "local ",
            "prod",
            "production\n",
        ] {
            assert_eq!(environment_from_label(label), None, "label {label:?}");
        }
    }

    /// Shape and existence are separate questions, and the constructor only
    /// answers the first. Diagnostics that conflated them would report a typo
    /// as working configuration.
    #[test]
    fn a_well_formed_configuration_can_still_name_nothing() {
        let present = directory("resolvable");
        assert!(configuration(present.clone(), present.clone()).paths_resolvable());

        let mut absent = present.clone();
        absent.push("no-such-directory");
        let typo = configuration(absent, present);
        // Well formed...
        assert!(typo.working_directory().is_absolute());
        // ...and nothing is there.
        assert!(!typo.paths_resolvable());
        assert_eq!(
            resolve(&git_status(), &typo),
            Err(ResolutionError::WorkingDirectoryUnresolvable)
        );
    }

    #[test]
    fn canonical_paths_are_bounded() {
        let long = PathBuf::from(format!("/{}", "a".repeat(MAX_PATH_BYTES)));
        assert_eq!(bounded_utf8(&long), Err(ResolutionError::PathTooLong));

        let mut deep = PathBuf::from("/");
        for _ in 0..128 {
            deep.push("d");
        }
        assert_eq!(
            bounded_utf8(&deep),
            Err(ResolutionError::TooManyPathSegments)
        );

        assert!(bounded_utf8(Path::new("/repo/src")).is_ok());

        // Both bounds pinned from below as well. Without these the checks are
        // only constrained from above, and tightening either by one -- refusing
        // a path of exactly the documented size -- changes nothing any test can
        // see. That direction cannot turn a deny into an allow, but it refuses
        // work the documentation promises, which is its own defect.
        let at_byte_limit = PathBuf::from(format!("/{}", "a".repeat(MAX_PATH_BYTES - 1)));
        assert_eq!(at_byte_limit.as_os_str().len(), MAX_PATH_BYTES);
        assert!(
            bounded_utf8(&at_byte_limit).is_ok(),
            "a path of exactly the byte limit is allowed"
        );

        let mut at_segment_limit = PathBuf::from("/");
        // The root counts as a component, so this loop adds one fewer.
        for _ in 1..MAX_PATH_SEGMENTS {
            at_segment_limit.push("d");
        }
        assert_eq!(at_segment_limit.components().count(), MAX_PATH_SEGMENTS);
        assert!(
            bounded_utf8(&at_segment_limit).is_ok(),
            "a path of exactly the segment limit is allowed"
        );
    }

    /// Every reason a resolution failed reaches the operator as distinct,
    /// non-empty text.
    ///
    /// Every variant here is `indeterminate` to the caller, so the message is
    /// the only thing that distinguishes "the boundary does not canonicalize"
    /// from "a path operand does not". An empty or duplicated message turns a
    /// diagnosable misconfiguration into an unexplained refusal.
    #[test]
    fn every_resolution_error_renders_a_distinct_message() {
        let all = [
            ResolutionError::OperationKindUnsupported,
            ResolutionError::OperandsUnexpectedForKind,
            ResolutionError::PathOperandUnresolvable,
            ResolutionError::EffectUnsupported,
            ResolutionError::RepositoryBoundaryUnresolvable,
            ResolutionError::WorkingDirectoryUnresolvable,
            ResolutionError::NonUtf8Path,
            ResolutionError::PathTooLong,
            ResolutionError::TooManyPathSegments,
            ResolutionError::TargetKindUnrepresentable,
            ResolutionError::CreationTargetExists,
        ];

        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for error in all {
            let rendered = match error {
                // Exhaustive on purpose. A variant added later stops compiling
                // here until it is named, so this test cannot silently fall
                // behind the enum it claims to cover.
                ResolutionError::OperationKindUnsupported
                | ResolutionError::OperandsUnexpectedForKind
                | ResolutionError::PathOperandUnresolvable
                | ResolutionError::EffectUnsupported
                | ResolutionError::RepositoryBoundaryUnresolvable
                | ResolutionError::WorkingDirectoryUnresolvable
                | ResolutionError::NonUtf8Path
                | ResolutionError::PathTooLong
                | ResolutionError::TooManyPathSegments
                | ResolutionError::TargetKindUnrepresentable
                | ResolutionError::CreationTargetExists => error.to_string(),
            };
            assert!(!rendered.is_empty(), "{error:?} renders nothing");
            assert!(seen.insert(rendered), "{error:?} shares another message");
        }
        assert_eq!(seen.len(), all.len());
    }

    /// Retained red-first witness: containment decided by string prefix.
    ///
    /// Canonicalizes correctly, then throws the result away by comparing text.
    fn vulnerable_string_prefix_containment(configuration: &TrustedConfiguration) -> Containment {
        let boundary = match std::fs::canonicalize(configuration.repository_boundary()) {
            Ok(path) => path,
            Err(error) => unreachable!("witness boundary must canonicalize: {error}"),
        };
        let working = match std::fs::canonicalize(configuration.working_directory()) {
            Ok(path) => path,
            Err(error) => unreachable!("witness working directory must canonicalize: {error}"),
        };
        match (working.to_str(), boundary.to_str()) {
            (Some(working), Some(boundary)) if working.starts_with(boundary) => {
                Containment::RepositoryLocal
            }
            _ => Containment::CrossBoundary,
        }
    }

    /// Retained red-first witness: containment decided on the configured
    /// spelling, before canonicalization.
    fn vulnerable_lexical_containment(configuration: &TrustedConfiguration) -> Containment {
        if configuration
            .working_directory()
            .starts_with(configuration.repository_boundary())
        {
            Containment::RepositoryLocal
        } else {
            Containment::CrossBoundary
        }
    }

    fn fingerprint_for(
        command: &str,
        configuration: &TrustedConfiguration,
    ) -> RevalidationFingerprint {
        let candidate = supported(command);
        let resolved = match resolve(&candidate, configuration) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("{command} must resolve: {error}"),
        };
        let revision = match Version::new("1.1.0") {
            Ok(revision) => revision,
            Err(error) => unreachable!("test revision must be valid: {error}"),
        };
        resolved.fingerprint(candidate.operation_kind(), &revision)
    }

    /// The witness the design names by name: "target-set change ignored during
    /// revalidation".
    ///
    /// A fingerprint whose comparison misses a changed target set is worse than
    /// no fingerprint. Milestone 2 redeems an approval by revalidating, so a
    /// comparison that returns `Unchanged` for a different set of files is a
    /// mechanism for redeeming an approval against paths nobody approved --
    /// which is precisely the attack the fingerprint exists to prevent.
    #[test]
    fn red_first_witness_detects_a_target_set_change_ignored_during_revalidation() {
        let boundary = directory("revalidate");
        let working = directory("revalidate/worktree");
        for name in ["approved.txt", "substituted.txt"] {
            match std::fs::write(working.join(name), b"contents") {
                Ok(()) => {}
                Err(error) => unreachable!("test file must be writable: {error}"),
            }
        }
        let configuration = configuration(working, boundary);

        let approved = fingerprint_for("git log -- approved.txt", &configuration);
        let substituted = fingerprint_for("git log -- substituted.txt", &configuration);

        // Same command shape, same count, same everything except which file.
        assert_eq!(approved.target_count(), substituted.target_count());
        assert_eq!(approved.operation_kind(), substituted.operation_kind());
        assert_eq!(
            revalidate(&approved, &substituted),
            Revalidation::Changed(FingerprintChange::TargetSet)
        );
        assert_ne!(approved.digest(), substituted.digest());

        // Identity must revalidate, or the comparison would be trivially
        // "correct" by rejecting everything.
        assert_eq!(revalidate(&approved, &approved), Revalidation::Unchanged);
        assert_eq!(
            revalidate(
                &approved,
                &fingerprint_for("git log -- approved.txt", &configuration)
            ),
            Revalidation::Unchanged,
            "recomputing the same resolution must revalidate"
        );

        // The retained witness compares only the fields that are cheap to
        // compare and skips the set digest, so a substituted file passes.
        assert_eq!(
            vulnerable_revalidation_ignores_target_set(&approved, &substituted),
            Revalidation::Unchanged
        );
    }

    /// Reordering the same pathspecs is not a change.
    ///
    /// Behaviour-pinning rather than a security invariant: the fail-safe
    /// direction would be to call it changed. It is pinned because a
    /// revalidation that fails for a reason no operator can act on is one that
    /// gets switched off.
    #[test]
    fn target_order_does_not_affect_the_fingerprint() {
        let boundary = directory("order");
        let working = directory("order/worktree");
        for name in ["a.txt", "b.txt"] {
            match std::fs::write(working.join(name), b"contents") {
                Ok(()) => {}
                Err(error) => unreachable!("test file must be writable: {error}"),
            }
        }
        let configuration = configuration(working, boundary);

        assert_eq!(
            revalidate(
                &fingerprint_for("git log -- a.txt b.txt", &configuration),
                &fingerprint_for("git log -- b.txt a.txt", &configuration)
            ),
            Revalidation::Unchanged
        );
        // A duplicate is a different set, though: the count separates them.
        assert_eq!(
            revalidate(
                &fingerprint_for("git log -- a.txt", &configuration),
                &fingerprint_for("git log -- a.txt a.txt", &configuration)
            ),
            Revalidation::Changed(FingerprintChange::TargetCount)
        );
    }

    /// Distinct target sets must not frame to identical digest input.
    ///
    /// A newline is a legal filename character on Unix, so joining paths with
    /// one is ambiguous. These two sets have the same element count and the
    /// same joined bytes, so a separator-joined digest cannot tell them apart
    /// and the count check does not save it either.
    #[test]
    fn red_first_witness_detects_ambiguous_target_framing() {
        let left = ["a\nb".to_owned(), "c".to_owned()];
        let right = ["a".to_owned(), "b\nc".to_owned()];

        let mut framed_left = Vec::new();
        let mut framed_right = Vec::new();
        for target in &left {
            frame(&mut framed_left, target.as_bytes());
        }
        for target in &right {
            frame(&mut framed_right, target.as_bytes());
        }
        assert_ne!(
            Digest::of(&framed_left).value(),
            Digest::of(&framed_right).value(),
            "length-prefixed framing must distinguish these"
        );

        // The retained witness joins with a newline, and the two sets collide.
        assert_eq!(
            vulnerable_separator_joined_digest(&left).value(),
            vulnerable_separator_joined_digest(&right).value()
        );
    }

    #[test]
    fn a_configuration_file_is_parsed_strictly() {
        let directory = directory("config-parse");
        let body = format!(
            "# trusted configuration\nworking_directory = {}\nrepository_boundary = {}\n\nenvironment = local\n",
            directory.display(),
            directory.display()
        );
        match parse_configuration(&body) {
            Ok(configuration) => {
                assert_eq!(configuration.environment(), EnvironmentClass::Local);
                assert_eq!(configuration.repository_boundary(), directory);
            }
            Err(error) => unreachable!("a well-formed file must parse: {error:?}"),
        }

        let complete = format!(
            "working_directory = {}\nrepository_boundary = {}\nenvironment = local\n",
            directory.display(),
            directory.display()
        );
        let cases = [
            // A key repeated is refused rather than last-writer-wins: a line
            // appended to the end of the file must not silently move the
            // boundary every containment decision is measured against.
            (
                format!("{complete}repository_boundary = {}\n", directory.display()),
                ConfigurationError::FileDuplicateKey,
            ),
            // A key this build does not understand is refused, not skipped.
            // Skipping turns a typo into an absent value, and there are no
            // defaults for an absent value to fall back to.
            (
                format!("{complete}repositry_boundary = /tmp\n"),
                ConfigurationError::FileUnknownKey,
            ),
            (
                "working_directory = /repo\n".to_owned(),
                ConfigurationError::FileMissingKey,
            ),
            (
                format!("{complete}not a pair\n"),
                ConfigurationError::FileMalformed,
            ),
            (
                format!("{complete}environment=\n"),
                ConfigurationError::FileMalformed,
            ),
            // An empty key and an empty value are each malformed on their own,
            // which is why the pair is checked with `||`. Both would still be
            // refused under `&&` -- an empty key reaches the unknown-key arm,
            // an empty value reaches the constructor as a relative path -- but
            // by a later check that was never meant to carry this, and
            // reporting the wrong reason for a refusal is how a malformed file
            // gets diagnosed as the wrong problem.
            (
                format!("{complete} = local\n"),
                ConfigurationError::FileMalformed,
            ),
            (
                format!("{complete}working_directory =\n"),
                ConfigurationError::FileMalformed,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(parse_configuration(&body), Err(expected), "body: {body:?}");
        }

        // `unknown` is not a label a file may assert, exactly as it is not one
        // a caller may pass.
        let unknown = format!(
            "working_directory = {}\nrepository_boundary = {}\nenvironment = unknown\n",
            directory.display(),
            directory.display()
        );
        assert_eq!(
            parse_configuration(&unknown),
            Err(ConfigurationError::FileMalformed)
        );
    }

    /// Configuration anyone may write is not trusted configuration.
    ///
    /// The rule is asserted on every platform even though it can only be
    /// *applied* on Unix, because the decision is a pure function of the mode.
    /// Asserting it only under `#[cfg(unix)]` would leave it untested on two of
    /// the three CI platforms while appearing covered.
    #[test]
    fn red_first_witness_detects_a_loader_that_ignores_permissions() {
        // Owner-only and owner-plus-group-read are fine; anything that lets
        // another account write is not.
        assert!(permissions_are_exclusive(0o600));
        assert!(permissions_are_exclusive(0o644));
        assert!(permissions_are_exclusive(0o444));
        assert!(!permissions_are_exclusive(0o666));
        assert!(!permissions_are_exclusive(0o620), "group-writable");
        assert!(!permissions_are_exclusive(0o602), "world-writable");
        assert!(!permissions_are_exclusive(0o777));

        // The retained witness checks that the file is readable and calls that
        // a permission check. It accepts a world-writable boundary definition.
        assert!(vulnerable_permissions_check(0o666));
        assert!(vulnerable_permissions_check(0o777));
    }

    #[test]
    fn a_missing_configuration_file_is_an_error_rather_than_a_default() {
        let mut absent = directory("config-absent");
        absent.push("no-such-file.conf");
        assert_eq!(
            TrustedConfiguration::from_file(&absent),
            Err(ConfigurationError::FileUnreadable)
        );
    }

    #[test]
    fn a_configuration_file_round_trips_from_disk() {
        let directory = directory("config-file");
        let path = directory.join("ofw.conf");
        let body = format!(
            "working_directory = {}\nrepository_boundary = {}\nenvironment = test\n",
            directory.display(),
            directory.display()
        );
        match std::fs::write(&path, body.as_bytes()) {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
        match TrustedConfiguration::from_file(&path) {
            Ok(configuration) => assert_eq!(configuration.environment(), EnvironmentClass::Test),
            Err(error) => unreachable!("the file must load: {error:?}"),
        }
    }

    /// The configuration-file size bound is enforced at its boundary.
    ///
    /// Both directions matter and they fail differently. Refusing at exactly
    /// the limit denies a file the documentation says is acceptable; refusing
    /// *only* at one byte over -- which is what replacing `>` with `==` does --
    /// leaves everything larger unbounded, so the check stops being a bound at
    /// all. A single over-limit case lands on the one value that mutation still
    /// rejects, which is why there are three of them here.
    #[test]
    fn the_configuration_size_bound_holds_at_its_boundary() {
        let directory = directory("config-size");
        let path = directory.join("bounded.conf");
        let body = format!(
            "working_directory = {}\nrepository_boundary = {}\nenvironment = local\n",
            directory.display(),
            directory.display()
        );
        let limit = match usize::try_from(MAX_CONFIGURATION_BYTES) {
            Ok(limit) => limit,
            Err(error) => unreachable!("the byte limit must fit a usize: {error}"),
        };

        // Comment lines are ignored, so the file can be padded to an exact size
        // without changing what it configures.
        let write_file_of = |total: usize| {
            let contents = format!("{body}#{}\n", "p".repeat(total - body.len() - 2));
            assert_eq!(contents.len(), total, "the fixture is exact");
            match std::fs::write(&path, contents.as_bytes()) {
                Ok(()) => {}
                Err(error) => unreachable!("test file must be writable: {error}"),
            }
        };

        write_file_of(limit);
        assert!(
            TrustedConfiguration::from_file(&path).is_ok(),
            "a file of exactly the limit is accepted"
        );

        for excess in [1, 2, 4_096] {
            write_file_of(limit + excess);
            assert_eq!(
                TrustedConfiguration::from_file(&path),
                Err(ConfigurationError::FileTooLarge),
                "a file {excess} bytes over the limit must be refused"
            );
        }
    }

    /// A creation resolves to a definite place that is not there yet.
    ///
    /// The design's rule for a write target: canonicalize the nearest existing
    /// ancestor and append the remaining components without claiming they
    /// exist. Without it every file creation would be `indeterminate`, because
    /// a path that does not exist does not canonicalize -- which is the correct
    /// answer for a read and the wrong one for a write.
    #[test]
    fn a_creation_resolves_through_its_nearest_existing_ancestor() {
        let boundary = directory("create");
        let working = directory("create/worktree");
        let configuration = configuration(working.clone(), boundary);

        let resolved = match resolve(
            &patch(&["*** Add File: a/b/c/new.txt", "+x"]),
            &configuration,
        ) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("a creation must resolve: {error}"),
        };

        assert_eq!(resolved.context().containment, Containment::RepositoryLocal);
        assert_eq!(
            resolved.context().target_completeness,
            TargetCompleteness::Complete
        );
        // Cleanly reversible, and only because nothing was overwritten -- see
        // the creation-target check below, which is what makes that true.
        assert_eq!(resolved.context().reversibility, Reversibility::Reversible);
        assert_eq!(resolved.canonical_targets().len(), 1);
        let Some(target) = resolved.canonical_targets().first() else {
            unreachable!("a creation resolves one target")
        };
        assert!(target.ends_with("new.txt"), "got {target}");
        // The missing components are appended, not invented somewhere else:
        // the result still sits under the canonicalized working directory.
        let canonical_working = match super::canonicalize(&working) {
            Some(path) => path,
            None => unreachable!("the test working directory must canonicalize"),
        };
        assert!(
            Path::new(target).starts_with(&canonical_working),
            "got {target}"
        );
        // ...and the path it names is genuinely absent, which is the whole
        // point: resolution must not have created or required anything.
        assert!(!Path::new(target).exists());
    }

    /// A creation whose target is already there is refused, not resolved.
    ///
    /// The document says create; the filesystem says something is in the way.
    /// Applying it would overwrite, which is an update -- and `Create` is the
    /// one effect this crate calls cleanly reversible, so accepting the
    /// mismatch would call an overwrite reversible.
    ///
    /// The check is sound across the whole target list because of how the
    /// grammar picks a document's effect: create is the least consequential of
    /// the four, so it can only be the maximum when every operation is one.
    #[test]
    fn a_creation_over_an_existing_path_is_refused() {
        let boundary = directory("create-collision");
        let working = directory("create-collision/worktree");
        match std::fs::write(working.join("taken.txt"), b"already here") {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
        let configuration = configuration(working, boundary);

        assert_eq!(
            resolve(&patch(&["*** Add File: taken.txt", "+x"]), &configuration),
            Err(ResolutionError::CreationTargetExists)
        );
        // One collision fails the whole document, like an unresolvable operand.
        assert_eq!(
            resolve(
                &patch(&[
                    "*** Add File: fresh.txt",
                    "+x",
                    "*** Add File: taken.txt",
                    "+y"
                ]),
                &configuration
            ),
            Err(ResolutionError::CreationTargetExists)
        );
        // An *update* to the same existing path is fine: overwriting is what
        // an update is, and it is not called reversible.
        let updated = match resolve(
            &patch(&["*** Update File: taken.txt", "@@", "+y"]),
            &configuration,
        ) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("an update must resolve: {error}"),
        };
        assert_eq!(
            updated.context().reversibility,
            Reversibility::ConditionallyRecoverable
        );
    }

    /// Every patch effect gets the reversibility it can actually be argued for.
    ///
    /// Overwriting, removing and renaming all destroy something, and whether it
    /// comes back depends on whether it was committed. This crate deliberately
    /// does not read `.git` or invoke git, so it cannot know -- and
    /// `ConditionallyRecoverable` states the category without asserting the
    /// condition holds. None of these reaches the baseline's allow row, which
    /// requires `Reversible`.
    #[test]
    fn each_patch_effect_gets_the_reversibility_it_can_be_argued_for() {
        let boundary = directory("reversibility");
        let working = directory("reversibility/worktree");
        for name in ["present.txt", "other.txt"] {
            match std::fs::write(working.join(name), b"contents") {
                Ok(()) => {}
                Err(error) => unreachable!("test file must be writable: {error}"),
            }
        }
        let configuration = configuration(working, boundary);

        let create: &[&str] = &["*** Add File: fresh.txt", "+x"];
        let update: &[&str] = &["*** Update File: present.txt", "@@", "+x"];
        let delete: &[&str] = &["*** Delete File: present.txt"];
        let moved: &[&str] = &["*** Update File: present.txt", "*** Move to: renamed.txt"];

        let cases: [(&[&str], Reversibility); 4] = [
            (create, Reversibility::Reversible),
            (update, Reversibility::ConditionallyRecoverable),
            (delete, Reversibility::ConditionallyRecoverable),
            (moved, Reversibility::ConditionallyRecoverable),
        ];
        for (lines, expected) in cases {
            let resolved = match resolve(&patch(lines), &configuration) {
                Ok(resolved) => resolved,
                Err(error) => unreachable!("{lines:?} must resolve: {error}"),
            };
            assert_eq!(resolved.context().reversibility, expected, "{lines:?}");
        }
    }

    /// A move names both ends, and both are resolved.
    #[test]
    fn a_move_resolves_its_source_and_its_destination() {
        let boundary = directory("move");
        let working = directory("move/worktree");
        match std::fs::write(working.join("before.txt"), b"contents") {
            Ok(()) => {}
            Err(error) => unreachable!("test file must be writable: {error}"),
        }
        let configuration = configuration(working, boundary);

        let resolved = match resolve(
            &patch(&["*** Update File: before.txt", "*** Move to: after.txt"]),
            &configuration,
        ) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("a move must resolve: {error}"),
        };
        // Two targets: one that exists and one that does not. A resolver that
        // refused the second, or silently dropped it, would describe a move as
        // touching half of what it touches.
        assert_eq!(resolved.canonical_targets().len(), 2);
        assert_eq!(resolved.context().containment, Containment::RepositoryLocal);
    }

    /// A write whose working directory is not there is unresolvable, not
    /// resolvable-by-string.
    ///
    /// Retained red-first witness for the write path specifically. The rule for
    /// a creation target -- append components nobody canonicalized -- is one
    /// step from appending *everything* and never touching the filesystem at
    /// all, and the result of that shortcut looks identical: an absolute path
    /// under the configured working directory, reported as fully resolved.
    /// Every containment guarantee in this crate rests on the ancestor having
    /// been canonicalized.
    #[test]
    fn red_first_witness_detects_a_write_resolved_without_canonicalizing() {
        let boundary = directory("write-witness");
        let mut absent = boundary.clone();
        absent.push("no-such-worktree");
        let configuration = configuration(absent.clone(), boundary);

        assert_eq!(
            resolve(&patch(&["*** Add File: new.txt", "+x"]), &configuration),
            Err(ResolutionError::WorkingDirectoryUnresolvable)
        );

        // The retained shortcut reports a resolved, plausible-looking target
        // under a directory that is not there.
        let vulnerable = vulnerable_lexical_write_target(&absent, "new.txt");
        assert!(vulnerable.ends_with("new.txt"));
        assert!(vulnerable.is_absolute());
        assert!(!vulnerable.exists());
    }

    /// Retained red-first witness: a write target built by joining strings,
    /// with nothing canonicalized at any point.
    fn vulnerable_lexical_write_target(working: &Path, operand: &str) -> PathBuf {
        working.join(operand)
    }

    /// A creation through a symlinked ancestor escapes, and is seen to escape.
    ///
    /// This is the only case that can tell "canonicalize the nearest existing
    /// ancestor" apart from "join the strings". For a path with no links and no
    /// `.`/`..` components -- which the grammar guarantees -- the lexical join
    /// and the canonical form are the same bytes, so every other test here
    /// passes just as well against a resolver that never canonicalizes at all.
    ///
    /// The grammar refuses absolute paths and traversal, so a link is the whole
    /// of what is left: `escape/new.txt` where `escape` is a symlink out of the
    /// worktree is a relative, traversal-free path that lands anywhere.
    ///
    /// **Unix only, and that is a real gap, not a formality.** Creating a
    /// symlink on Windows needs developer mode or elevation, and a test that
    /// quietly skipped would pass while proving nothing -- so it does not exist
    /// on Windows rather than existing and lying. Two of the three CI platforms
    /// run it. Windows junctions would cover the same ground and need the
    /// Win32 API, which `forbid(unsafe_code)` puts out of reach here.
    #[cfg(unix)]
    #[test]
    fn a_creation_through_a_symlinked_ancestor_is_cross_boundary() {
        let boundary = directory("symlink-escape");
        let working = directory("symlink-escape/worktree");
        let outside = directory("symlink-escape-outside");

        let link = working.join("escape");
        // Removed first so a rerun in the same process id is not defeated by a
        // link left behind, which would make this pass without testing.
        let _ = std::fs::remove_file(&link);
        match std::os::unix::fs::symlink(&outside, &link) {
            Ok(()) => {}
            Err(error) => unreachable!("the test symlink must be creatable: {error}"),
        }
        let configuration = configuration(working, boundary);

        let resolved = match resolve(
            &patch(&["*** Add File: escape/planted.txt", "+x"]),
            &configuration,
        ) {
            Ok(resolved) => resolved,
            Err(error) => unreachable!("a creation through a link must resolve: {error}"),
        };

        // The ancestor canonicalized to somewhere else, so the target is
        // outside the boundary and the operation is cross-boundary -- which the
        // baseline denies outright.
        //
        // Note what the fixture also happens to cover: the outside directory is
        // a *sibling* whose name begins with the boundary's, so a containment
        // check comparing canonical paths as strings rather than by component
        // would call this repository-local. `vulnerable_string_prefix_containment`
        // is the retained witness for that, and this is a second, independent
        // input that would defeat it.
        assert_eq!(resolved.context().containment, Containment::CrossBoundary);
        let Some(target) = resolved.canonical_targets().first() else {
            unreachable!("a creation resolves one target")
        };
        // Asserted as "landed where the link points", not as "the link's name
        // is absent from the string". The first spelling of this test used the
        // latter and could never pass, because the fixture directory is itself
        // named `...-escape-outside` -- a reminder that a substring check on a
        // path is answering a question about text, not about location.
        let canonical_outside = match super::canonicalize(&outside) {
            Some(path) => path,
            None => unreachable!("the outside directory must canonicalize"),
        };
        assert!(
            Path::new(target).starts_with(&canonical_outside),
            "the ancestor was not canonicalized: {target}"
        );

        // The retained shortcut keeps the link in the path, so the result still
        // reads as sitting under the worktree.
        let vulnerable = vulnerable_lexical_write_target(
            configuration.working_directory(),
            "escape/planted.txt",
        );
        assert!(vulnerable.starts_with(configuration.working_directory()));
    }

    /// The fingerprint records how many targets it covers.
    ///
    /// The count is one of the fields `revalidate` compares, and Milestone 2
    /// binds an approval to the fingerprint as a whole. A constant count would
    /// let an approval taken over two files revalidate against one, so the
    /// existing coverage -- two fingerprints agreeing with each other -- is not
    /// enough: both agree just as well when both are wrong.
    #[test]
    fn the_fingerprint_records_how_many_targets_it_covers() {
        let boundary = directory("fingerprint-count");
        let working = directory("fingerprint-count/worktree");
        for name in ["one.txt", "two.txt"] {
            match std::fs::write(working.join(name), b"contents") {
                Ok(()) => {}
                Err(error) => unreachable!("test file must be writable: {error}"),
            }
        }
        let configuration = configuration(working, boundary);

        // A repository-scoped read covers the repository: one target.
        assert_eq!(
            fingerprint_for("git status", &configuration).target_count(),
            1
        );
        assert_eq!(
            fingerprint_for("git log -- one.txt", &configuration).target_count(),
            1
        );
        assert_eq!(
            fingerprint_for("git log -- one.txt two.txt", &configuration).target_count(),
            2
        );
    }

    /// Retained red-first witness: a "permission check" that only confirms the
    /// file can be read.
    const fn vulnerable_permissions_check(mode: u32) -> bool {
        mode & 0o400 != 0
    }

    /// Retained red-first witness: revalidation that skips the target set.
    fn vulnerable_revalidation_ignores_target_set(
        recorded: &RevalidationFingerprint,
        current: &RevalidationFingerprint,
    ) -> Revalidation {
        if recorded.operation_kind != current.operation_kind {
            return Revalidation::Changed(FingerprintChange::OperationKind);
        }
        if recorded.target_count != current.target_count {
            return Revalidation::Changed(FingerprintChange::TargetCount);
        }
        Revalidation::Unchanged
    }

    /// Retained red-first witness: a target-set digest built by joining paths
    /// with a separator instead of length-prefixing them.
    fn vulnerable_separator_joined_digest(targets: &[String]) -> Digest {
        Digest::of(targets.join("\n").as_bytes())
    }

    /// Retained red-first witness: target scope keyed on the operation kind
    /// alone, ignoring how many operands the candidate actually carries.
    ///
    /// This is the shape `target_scope` had while nothing took operands, kept
    /// so the reason it stopped being safe stays visible.
    fn vulnerable_scope_ignores_operand_count(
        operation_kind: &str,
        path_operands: usize,
    ) -> Option<TargetScope> {
        let _ = path_operands;
        match operation_kind {
            "git.status" | "git.rev_parse" | "git.log" | "git.diff" => {
                Some(TargetScope::Repository)
            }
            _ => None,
        }
    }
}
