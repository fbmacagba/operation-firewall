//! Strict v1 policy-bundle deserialization.
//!
//! A policy bundle is untrusted input read from disk. It is parsed the way
//! untrusted input has to be: bounded first, then shape, then values, with no
//! step repairing what the previous one rejected.
//!
//! # A bundle is all or nothing
//!
//! The single most important property here is that a bundle with one bad rule
//! is a **bad bundle**, not a good bundle with one fewer rule. "Be liberal in
//! what you accept" inverts catastrophically for a policy file: the thing
//! silently dropped is a restriction, so a rule that fails to parse and gets
//! skipped is a rule that stops denying. `red_first_witness_detects_skipped_rules`
//! retains that behaviour and shows a deny disappearing.
//!
//! The corollary belongs to the caller and is just as load-bearing: a bundle
//! that failed to load is **not** an empty policy. Activation is unhealthy and
//! every decision is indeterminate until it is fixed, because "we could not
//! read the restrictions" and "there are no restrictions" are the same
//! observation only if you are willing to fail open.
//!
//! # Errors carry no policy content
//!
//! `serde_json`'s own error messages quote the input. None of them reaches
//! [`BundleError`], which is a payload-free enum: a policy file can contain
//! paths, internal identifiers and organisation structure, and diagnostics are
//! copied into bug reports.

use std::collections::BTreeSet;

use ofw_contracts::{
    BlastRadius, EnvironmentClass, ExternalPolicyLayer, Identifier, NamespacedName,
    OperationEffect, Restriction, Reversibility, Version,
};
use serde::Deserialize;

use crate::{PolicyError, RestrictionRule, Selectors, ValidatedPolicyBundle};

/// The only schema version this build understands.
///
/// An unsupported version fails explicitly rather than being parsed on a
/// best-effort basis. A future contract may move a field whose absence this
/// build would read as "not restricted".
pub const SUPPORTED_SCHEMA_VERSION: &str = "1.0";

/// Compiled bound on one bundle file, applied before parsing.
pub const MAX_BUNDLE_BYTES: usize = 1_048_576;

const MAX_SCOPE_VALUES: usize = 64;
const MAX_NAME_SET: usize = 64;
const MAX_SAFER_ALTERNATIVES: usize = 8;
const MAX_CANONICAL_PATH_PREFIXES: usize = 64;
const MAX_ISSUED_AT_LENGTH: usize = 35;

/// Why a bundle could not be loaded.
///
/// Every variant is a refusal to load, and a refusal to load is never a
/// weaker policy -- see the module note on activation health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleError {
    TooLarge,
    NotUtf8,
    /// The bytes are not JSON.
    MalformedSyntax,
    /// Valid JSON that is not a valid v1 bundle: an unknown field, an unknown
    /// enum variant such as `"effect": "allow"`, a primitive that failed its
    /// contract validation, or a missing required field.
    MalformedShape,
    UnsupportedSchemaVersion,
    InvalidIssuedAt,
    /// A present array that the contract requires to be non-empty.
    EmptySelectorValues,
    DuplicateValue,
    TooManyValues,
    /// Structural validation by the policy types themselves.
    Invalid(PolicyError),
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::TooLarge => "policy bundle exceeds the configured byte limit",
            Self::NotUtf8 => "policy bundle is not valid UTF-8",
            Self::MalformedSyntax => "policy bundle is not valid JSON",
            Self::MalformedShape => "policy bundle does not match the v1 contract",
            Self::UnsupportedSchemaVersion => {
                "policy bundle declares an unsupported schema version"
            }
            Self::InvalidIssuedAt => "policy bundle issue timestamp is not a bounded date-time",
            Self::EmptySelectorValues => "policy bundle contains an empty selector array",
            Self::DuplicateValue => "policy bundle contains a duplicate value in a unique array",
            Self::TooManyValues => "policy bundle exceeds a contract array bound",
            Self::Invalid(_) => "policy bundle failed structural validation",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BundleError {}

impl From<PolicyError> for BundleError {
    fn from(value: PolicyError) -> Self {
        Self::Invalid(value)
    }
}

/// Parses one v1 policy bundle.
///
/// Returns a single error for the whole document. There is deliberately no
/// variant that reports partial success.
pub fn parse_bundle(bytes: &[u8]) -> Result<ValidatedPolicyBundle, BundleError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| BundleError::NotUtf8)?;

    // The error's own message quotes the input; only its classification
    // crosses this boundary.
    let document: BundleDocument = serde_json::from_str(text).map_err(|error| {
        match error.classify() {
            serde_json::error::Category::Data => BundleError::MalformedShape,
            // Syntax, Eof and Io are all "these bytes are not a JSON document".
            _ => BundleError::MalformedSyntax,
        }
    })?;

    if document.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedSchemaVersion);
    }
    validate_issued_at(&document.issued_at)?;

    // Scope is parsed and bounded but not yet used to select which bundles
    // apply. Filtering a bundle out by scope removes restrictions, and a
    // selection rule that can remove restrictions has to be built with the
    // same care as one that adds them. Until it is, every supplied bundle
    // applies -- over-restrictive, which is the safe direction, and recorded
    // as a limitation rather than left to be inferred.
    let _ = unique_set(document.scope.tenant_ids, MAX_SCOPE_VALUES)?;
    let _ = unique_set(document.scope.repository_ids, MAX_SCOPE_VALUES)?;
    let _ = unique_set(document.scope.environments, MAX_SCOPE_VALUES)?;

    let mut rules = Vec::with_capacity(document.rules.len());
    for rule in document.rules {
        // `?` and not a filter: one unconvertible rule fails the bundle.
        rules.push(convert_rule(rule)?);
    }

    Ok(ValidatedPolicyBundle::new(
        document.layer.into(),
        document.bundle_id,
        document.bundle_version,
        rules,
    )?)
}

fn convert_rule(rule: RuleDocument) -> Result<RestrictionRule, BundleError> {
    let mut selectors = Selectors::default();
    if let Some(kinds) = present(rule.selectors.operation_kinds)? {
        selectors = selectors.with_operation_kinds(unique_set(kinds, MAX_NAME_SET)?);
    }
    if let Some(effects) = present(rule.selectors.operation_effects)? {
        selectors = selectors.with_operation_effects(unique_set(effects, MAX_NAME_SET)?);
    }
    if let Some(kinds) = present(rule.selectors.target_kinds)? {
        selectors = selectors.with_target_kinds(unique_set(kinds, MAX_NAME_SET)?);
    }
    if let Some(environments) = present(rule.selectors.environments)? {
        selectors = selectors.with_environments(unique_set(environments, MAX_NAME_SET)?);
    }
    if let Some(values) = present(rule.selectors.reversibility)? {
        selectors = selectors.with_reversibility(unique_set(values, MAX_NAME_SET)?);
    }
    if let Some(values) = present(rule.selectors.blast_radius)? {
        selectors = selectors.with_blast_radius(unique_set(values, MAX_NAME_SET)?);
    }
    if let Some(prefixes) = present(rule.selectors.canonical_path_prefixes)? {
        let prefixes = unique_set(prefixes, MAX_CANONICAL_PATH_PREFIXES)?;
        selectors = selectors.with_canonical_path_prefixes(prefixes)?;
    }

    if rule.safer_alternatives.len() > MAX_SAFER_ALTERNATIVES {
        return Err(BundleError::TooManyValues);
    }

    Ok(RestrictionRule::new(
        rule.rule_id,
        rule.effect,
        selectors,
        unique_set(rule.risk_categories, MAX_NAME_SET)?,
        rule.rationale,
        rule.safer_alternatives,
    )?)
}

/// Rejects an array that is present and empty.
///
/// The contract's selector arrays are `minItems: 1`. An empty one would widen
/// the rule rather than narrow it -- a dimension with no values selected is a
/// dimension that matches everything -- so accepting it would silently turn a
/// targeted rule into a broad one. That direction is *more* restrictive and
/// therefore safe, which is exactly why it must still be rejected: silently
/// changing what a rule means is a defect even when the change is safe.
fn present<T>(values: Option<Vec<T>>) -> Result<Option<Vec<T>>, BundleError> {
    match values {
        Some(values) if values.is_empty() => Err(BundleError::EmptySelectorValues),
        other => Ok(other),
    }
}

/// Converts to a set while refusing what a set would silently absorb.
///
/// The contract marks these arrays `uniqueItems`. Collecting into a set would
/// accept a duplicate by deduplicating it, which is a document that violates
/// the contract being loaded anyway.
fn unique_set<T: Ord>(values: Vec<T>, maximum: usize) -> Result<BTreeSet<T>, BundleError> {
    if values.len() > maximum {
        return Err(BundleError::TooManyValues);
    }
    let count = values.len();
    let set: BTreeSet<T> = values.into_iter().collect();
    if set.len() != count {
        return Err(BundleError::DuplicateValue);
    }
    Ok(set)
}

/// Bounded structural check on the issue timestamp.
///
/// This is not a calendar-aware RFC 3339 parser and does not claim to be: it
/// bounds the length and confirms the shape is date-time-like, so an
/// unbounded or obviously wrong value cannot enter. Full timestamp semantics
/// arrive with the audit clock, which is where a wrong timestamp actually
/// changes a decision.
fn validate_issued_at(value: &str) -> Result<(), BundleError> {
    if value.is_empty() || value.len() > MAX_ISSUED_AT_LENGTH {
        return Err(BundleError::InvalidIssuedAt);
    }
    // `1970-01-01T00:00:00Z` is the shortest accepted form: the shape below,
    // plus at least one byte of zone.
    if value.len() <= ISSUED_AT_SHAPE.len() {
        return Err(BundleError::InvalidIssuedAt);
    }
    // Zipped against the shape rather than indexed at fixed offsets. The
    // offsets were correct, and their correctness depended on reading the
    // length check above together with six subscripts below it -- and in this
    // binary an out-of-bounds panic is exit 101, which the Codex host treats as
    // fail-open. `zip` stops at the shorter of the two, so the read cannot
    // outrun the input whatever the guard above does.
    let shaped = value
        .bytes()
        .zip(ISSUED_AT_SHAPE.iter())
        .all(|(byte, expected)| {
            if *expected == DIGIT {
                byte.is_ascii_digit()
            } else {
                byte == *expected
            }
        });
    if !shaped {
        return Err(BundleError::InvalidIssuedAt);
    }
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
    {
        return Err(BundleError::InvalidIssuedAt);
    }
    Ok(())
}

/// The stand-in for "any digit" in [`ISSUED_AT_SHAPE`].
///
/// `d` is safe to overload: no position in a date-time shape requires a
/// literal `d`.
const DIGIT: u8 = b'd';

/// The shape every accepted timestamp shares, over its leading bytes.
///
/// Anything after this is zone, whose forms vary (`Z`, `+00:00`, a fractional
/// second and then either) and are bounded by length alone.
const ISSUED_AT_SHAPE: &[u8] = b"dddd-dd-ddTdd:dd:dd";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleDocument {
    schema_version: String,
    bundle_id: Identifier,
    bundle_version: Version,
    layer: ExternalPolicyLayer,
    issued_at: String,
    #[allow(
        dead_code,
        reason = "parsed and bounded; signature checking is Milestone 2"
    )]
    authority: AuthorityDocument,
    scope: ScopeDocument,
    rules: Vec<RuleDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityDocument {
    #[allow(dead_code, reason = "recorded by the contract; unused until approvals")]
    issuer_id: Identifier,
    #[allow(dead_code, reason = "recorded by the contract; unused until approvals")]
    key_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeDocument {
    tenant_ids: Vec<Identifier>,
    environments: Vec<EnvironmentClass>,
    repository_ids: Vec<Identifier>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDocument {
    rule_id: Identifier,
    /// Typed as [`Restriction`], which has no `Allow` variant. `"allow"` is an
    /// unknown variant here, not a value this code decides what to do with.
    effect: Restriction,
    selectors: SelectorsDocument,
    risk_categories: Vec<NamespacedName>,
    rationale: String,
    safer_alternatives: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorsDocument {
    #[serde(default)]
    operation_kinds: Option<Vec<NamespacedName>>,
    #[serde(default)]
    operation_effects: Option<Vec<OperationEffect>>,
    #[serde(default)]
    target_kinds: Option<Vec<NamespacedName>>,
    #[serde(default)]
    environments: Option<Vec<EnvironmentClass>>,
    #[serde(default)]
    reversibility: Option<Vec<Reversibility>>,
    #[serde(default)]
    blast_radius: Option<Vec<BlastRadius>>,
    #[serde(default)]
    canonical_path_prefixes: Option<Vec<String>>,
}
