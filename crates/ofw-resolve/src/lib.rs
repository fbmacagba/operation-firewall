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
/// This slice's only loader reads process environment variables (see the CLI).
/// That is explicit and outside the repository, but it is weaker than the
/// design's eventual requirement: a bounded configuration file whose ownership
/// and permissions are verified at startup. The gap is reported by
/// `ofw doctor` rather than left for a reader to discover.
///
/// The practical exposure today is nil rather than merely small: `environment`
/// only gates baseline rows that reach `allow`, and no operation in the
/// interpreted subset can reach `allow` at all. It becomes load-bearing the
/// moment a non-executing operation is interpreted, which is why the file
/// loader has to exist before that lands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedConfiguration {
    working_directory: PathBuf,
    repository_boundary: PathBuf,
    environment: EnvironmentClass,
}

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
    /// directory.
    Paths,
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
    // Only `Read` is derivable while the interpreted subset is read-only;
    // every other effect has to be argued for in the slice that introduces it.
    let reversibility = match candidate.effect() {
        OperationEffect::Read => Reversibility::Reversible,
        OperationEffect::Create
        | OperationEffect::Update
        | OperationEffect::Delete
        | OperationEffect::Move
        | OperationEffect::Execute
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
        _ => Err(ResolutionError::OperationKindUnsupported),
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
        ConfigurationError, Digest, FingerprintChange, MAX_PATH_BYTES, ResolutionError,
        Revalidation, RevalidationFingerprint, TargetScope, TrustedConfiguration, bounded_utf8,
        environment_from_label, frame, resolve, revalidate, target_scope,
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
        assert!(scoped.canonical_targets()[0].ends_with("tracked.txt"));

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
        assert!(!widened.canonical_targets()[0].ends_with("tracked.txt"));
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
