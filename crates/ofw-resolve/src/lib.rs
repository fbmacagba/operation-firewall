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
    BlastRadius, EnvironmentClass, NamespacedName, OperationEffect, Reversibility,
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
    /// The candidate carries extracted path operands. Resolving those is the
    /// slice that introduces the first operand-taking subcommand.
    PathTargetsUnsupported,
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
            Self::PathTargetsUnsupported => "operation carries path operands that are not resolved",
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
}

/// The contract name for a whole repository working tree as a target.
const REPOSITORY_TARGET_KIND: &str = "git.repository";

/// One resolved operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTargets {
    context: ResolvedContext,
    canonical_targets: Vec<String>,
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
}

/// Establishes the resolver-supplied facts for one interpreted operation.
pub fn resolve(
    candidate: &IntentCandidate,
    configuration: &TrustedConfiguration,
) -> Result<ResolvedTargets, ResolutionError> {
    // An operand this crate has not resolved must never be silently dropped.
    // Refusing outright costs the operation its proof, which denies; resolving
    // around it would produce a proof about targets nobody looked at.
    if !candidate.path_candidates().is_empty() {
        return Err(ResolutionError::PathTargetsUnsupported);
    }

    let scope = target_scope(candidate.operation_kind().as_str())?;

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

    Ok(ResolvedTargets {
        context: ResolvedContext {
            containment,
            target_completeness,
            environment: configuration.environment,
            blast_radius,
            reversibility,
        },
        canonical_targets,
        target_kinds,
    })
}

/// What the operation's targets are, keyed on the normalized operation kind.
///
/// Keyed on the *kind*, and deliberately not on "the interpreter extracted no
/// paths". Those two coincide exactly today, and they stop coinciding the
/// moment an operand-taking subcommand is interpreted: a pathspec-extraction
/// bug that dropped its operands would then resolve the entire working tree as
/// a complete, repository-local target and hand back a proof covering paths
/// nobody extracted. `red_first_witness_detects_scope_inferred_from_absent_paths`
/// retains that inference and shows it doing exactly that.
fn target_scope(operation_kind: &str) -> Result<TargetScope, ResolutionError> {
    match operation_kind {
        "git.status" | "git.rev_parse" => Ok(TargetScope::Repository),
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
        ConfigurationError, MAX_PATH_BYTES, ResolutionError, TargetScope, TrustedConfiguration,
        bounded_utf8, environment_from_label, resolve, target_scope,
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
        match ofw_intent::interpret("git status") {
            Ok(Classification::Supported(candidate)) => *candidate,
            other => unreachable!("git status must classify, got {other:?}"),
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

    #[test]
    fn red_first_witness_detects_scope_inferred_from_absent_paths() {
        // `git log` is a recognized subcommand that takes pathspecs. It is not
        // interpreted yet, so nothing extracts its operands.
        assert_eq!(
            target_scope("git.log"),
            Err(ResolutionError::OperationKindUnsupported)
        );
        // The retained witness infers scope from an empty candidate list, and
        // so reports the entire working tree as the target of a command whose
        // pathspecs were never read.
        assert_eq!(
            vulnerable_scope_from_absent_paths("git.log", 0),
            Some(TargetScope::Repository)
        );
        // It agrees with the real function wherever the real function decides,
        // so the difference is exactly the inference and not a coincidence.
        assert_eq!(
            vulnerable_scope_from_absent_paths("git.status", 0),
            Some(TargetScope::Repository)
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

    /// Retained red-first witness: target scope inferred from the absence of
    /// extracted paths rather than from the operation kind.
    fn vulnerable_scope_from_absent_paths(
        operation_kind: &str,
        path_candidate_count: usize,
    ) -> Option<TargetScope> {
        if path_candidate_count == 0 {
            return Some(TargetScope::Repository);
        }
        target_scope(operation_kind).ok()
    }
}
