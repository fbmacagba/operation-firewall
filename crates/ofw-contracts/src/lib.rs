#![forbid(unsafe_code)]

//! Validated domain primitives and their v1 wire vocabulary.
//!
//! # Deserialization goes through validation, never around it
//!
//! Every bounded newtype here deserializes via `try_from = "String"`, so the
//! only way to obtain one from JSON is the same constructor an in-process
//! caller must use. There is no `Deserialize` path that constructs an
//! unvalidated value, which is what stops a parsed contract from being weaker
//! than a hand-built one.
//!
//! Enum wire spellings are pinned by test against the JSON Schema contracts
//! rather than inherited from a rename attribute and hoped to match: a silent
//! rename is a silent contract break, and for a selector vocabulary it is a
//! rule that stops matching what it used to match.

use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A SHA-256 digest, rendered as lowercase hex.
///
/// A shared primitive rather than an audit one. Two independent consumers need
/// exactly this: an audit record, where a digest is the only way a
/// variable-length input may appear at all, and the resolver's revalidation
/// fingerprint, where it is how a target set is identified without carrying the
/// paths. Defining it once keeps those two from drifting into digests that look
/// alike and are not comparable.
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

    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }
}

const fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_NAMESPACED_NAME_LENGTH: usize = 128;
const MAX_VERSION_LENGTH: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct Identifier(String);

impl TryFrom<String> for Identifier {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        value.0
    }
}

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_identifier(&value, MAX_IDENTIFIER_LENGTH)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct NamespacedName(String);

impl TryFrom<String> for NamespacedName {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<NamespacedName> for String {
    fn from(value: NamespacedName) -> Self {
        value.0
    }
}

impl NamespacedName {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_identifier(&value, MAX_NAMESPACED_NAME_LENGTH)?;
        if !value.contains('.') {
            return Err(ContractError::MissingNamespace);
        }
        if value
            .split('.')
            .any(|segment| segment.is_empty() || !is_lower_identifier_segment(segment))
        {
            return Err(ContractError::InvalidNamespacedName);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct Version(String);

impl TryFrom<String> for Version {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Version> for String {
    fn from(value: Version) -> Self {
        value.0
    }
}

impl Version {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ContractError::Empty);
        }
        if value.len() > MAX_VERSION_LENGTH {
            return Err(ContractError::TooLong {
                maximum: MAX_VERSION_LENGTH,
                actual: value.len(),
            });
        }

        let suffix_index = value.find(['+', '-']);
        let (core, suffix) = match suffix_index {
            Some(index) => (&value[..index], Some(&value[index + 1..])),
            None => (value.as_str(), None),
        };
        let core_segments: Vec<_> = core.split('.').collect();
        let core_is_valid = (1..=3).contains(&core_segments.len())
            && core_segments.iter().all(|segment| {
                !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
            });
        let suffix_is_valid = suffix.is_none_or(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        });
        if !core_is_valid || !suffix_is_valid {
            return Err(ContractError::InvalidVersion);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which layer a rule came from.
///
/// Deliberately **not** deserializable. `Builtin` is the layer the built-in
/// safety baseline occupies, and a supplied bundle that could name it would be
/// claiming to be the baseline. External bundles use [`ExternalPolicyLayer`],
/// which cannot express `Builtin` at all -- a structural guard rather than a
/// validation step that a later refactor could drop.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    Builtin,
    Organization,
    User,
    Repository,
}

/// The layers a supplied policy bundle may declare.
///
/// The v1 policy-bundle contract admits `organization`, `user` and
/// `repository`. `builtin` is absent from this type for the reason above, so
/// `"layer": "builtin"` in a bundle file is an unknown variant and the bundle
/// is rejected outright.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPolicyLayer {
    Organization,
    User,
    Repository,
}

impl From<ExternalPolicyLayer> for PolicyLayer {
    fn from(value: ExternalPolicyLayer) -> Self {
        match value {
            ExternalPolicyLayer::Organization => Self::Organization,
            ExternalPolicyLayer::User => Self::User,
            ExternalPolicyLayer::Repository => Self::Repository,
        }
    }
}

impl PolicyLayer {
    #[must_use]
    pub const fn is_external(self) -> bool {
        !matches!(self, Self::Builtin)
    }
}

/// A restriction a rule may impose.
///
/// There is no `Allow` variant and there never may be. The v1 contract's rule
/// `effect` enum is `["ask", "deny"]`, so `"effect": "allow"` in a supplied
/// bundle is an unknown variant and the bundle is rejected -- a weakening is
/// not merely refused at validation time, it is inexpressible in the type the
/// deserializer targets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Restriction {
    Ask,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEffect {
    Read,
    Create,
    Update,
    Delete,
    Move,
    Execute,
    PermissionChange,
    Publish,
    UnknownMutation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    Local,
    Development,
    Test,
    Staging,
    Production,
    Shared,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    Recoverable,
    ConditionallyRecoverable,
    Irreversible,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    Single,
    Bounded,
    Broad,
    Unbounded,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    Empty,
    TooLong { maximum: usize, actual: usize },
    InvalidIdentifierCharacter { index: usize },
    MissingNamespace,
    InvalidNamespacedName,
    InvalidVersion,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value must not be empty"),
            Self::TooLong { maximum, actual } => {
                write!(formatter, "value length {actual} exceeds maximum {maximum}")
            }
            Self::InvalidIdentifierCharacter { index } => {
                write!(formatter, "invalid identifier character at byte {index}")
            }
            Self::MissingNamespace => formatter.write_str("name must contain a namespace"),
            Self::InvalidNamespacedName => {
                formatter.write_str("name contains an invalid namespace segment")
            }
            Self::InvalidVersion => {
                formatter.write_str("version does not match the v1 version syntax")
            }
        }
    }
}

impl std::error::Error for ContractError {}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), ContractError> {
    if value.is_empty() {
        return Err(ContractError::Empty);
    }
    if value.len() > maximum {
        return Err(ContractError::TooLong {
            maximum,
            actual: value.len(),
        });
    }

    for (index, byte) in value.bytes().enumerate() {
        let valid = if index == 0 {
            byte.is_ascii_alphanumeric()
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
        };
        if !valid {
            return Err(ContractError::InvalidIdentifierCharacter { index });
        }
    }
    Ok(())
}

fn is_lower_identifier_segment(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| {
        if index == 0 {
            byte.is_ascii_lowercase()
        } else {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BlastRadius, ContractError, Digest, EnvironmentClass, ExternalPolicyLayer, Identifier,
        MAX_IDENTIFIER_LENGTH, NamespacedName, OperationEffect, PolicyLayer, Restriction,
        Reversibility, Version, hex_nibble,
    };

    /// The digest is the exact SHA-256 of its input, hex-encoded.
    ///
    /// Pinned against a published test vector rather than against itself. Every
    /// self-consistent assertion available here -- that two calls agree, that
    /// different inputs differ, that the length is 64 -- passes just as well
    /// against a wrong encoder, and a mutation run proved it: `>>` swapped for
    /// `<<` and `&` for `|` in the encoding loop both survived, as did the
    /// arithmetic inside `hex_nibble`.
    ///
    /// That matters beyond tidiness. This digest is what the revalidation
    /// fingerprint is built from, so an encoder that collides or mislabels is a
    /// fingerprint that can be redeemed against the wrong target set.
    #[test]
    fn the_digest_matches_the_published_sha256_vectors() {
        // FIPS 180-4 / RFC 6234 worked examples.
        let vectors = [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, expected) in vectors {
            let digest = Digest::of(input.as_bytes());
            assert_eq!(digest.value(), expected, "input {input:?}");
            assert_eq!(digest.algorithm(), "sha256");
        }
    }

    /// Every nibble maps to its own hex character, across the whole range.
    ///
    /// `hex_nibble` is four lines of arithmetic and carried seven survivors.
    /// Asserted exhaustively because the range is sixteen values: there is no
    /// reason to sample a domain small enough to enumerate.
    #[test]
    fn every_nibble_maps_to_its_own_lowercase_hex_character() {
        let expected = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        for (value, character) in expected.into_iter().enumerate() {
            let nibble = u8::try_from(value).unwrap_or(u8::MAX);
            assert_eq!(hex_nibble(nibble), character, "nibble {value}");
        }
    }

    /// The built-in layer is the only one that is not external.
    ///
    /// This is the guard that stops a supplied policy bundle claiming to be the
    /// built-in baseline. It was tested — in `ofw-policy`, one crate away —
    /// which is why three mutations of it survived here: `cargo-mutants` runs a
    /// mutant against its own package's tests, so this list measures whether a
    /// crate holds its own invariants, not whether anything holds them.
    ///
    /// A guarantee whose only test lives in a consumer is fragile in a specific
    /// way: the consumer's test can be rewritten for unrelated reasons and the
    /// guarantee silently loses its last check. Asserted here as well, where it
    /// is defined.
    #[test]
    fn only_the_builtin_layer_is_not_external() {
        assert!(!PolicyLayer::Builtin.is_external());
        for layer in [
            PolicyLayer::Organization,
            PolicyLayer::User,
            PolicyLayer::Repository,
        ] {
            assert!(layer.is_external(), "{layer:?} is a supplied layer");
        }

        // Exhaustive on purpose: a layer added later stops compiling here until
        // its side of this question is stated.
        for layer in [
            PolicyLayer::Builtin,
            PolicyLayer::Organization,
            PolicyLayer::User,
            PolicyLayer::Repository,
        ] {
            match layer {
                PolicyLayer::Builtin
                | PolicyLayer::Organization
                | PolicyLayer::User
                | PolicyLayer::Repository => {}
            }
        }
    }

    /// Every accessor returns the value it was constructed from.
    ///
    /// Individually trivial, and collectively the reason ten mutants survived:
    /// nothing in this crate read an accessor back and compared it to its
    /// input, so replacing any of them with `""` or a constant changed nothing
    /// observable here.
    #[test]
    fn every_accessor_returns_what_it_was_constructed_from() {
        let identifier = match Identifier::new("org.baseline") {
            Ok(value) => value,
            Err(error) => unreachable!("test identifier must be valid: {error}"),
        };
        assert_eq!(identifier.as_str(), "org.baseline");
        assert_eq!(String::from(identifier.clone()), "org.baseline");

        let name = match NamespacedName::new("git.force_update") {
            Ok(value) => value,
            Err(error) => unreachable!("test name must be valid: {error}"),
        };
        assert_eq!(name.as_str(), "git.force_update");
        assert_eq!(String::from(name.clone()), "git.force_update");

        let version = match Version::new("1.2.0") {
            Ok(value) => value,
            Err(error) => unreachable!("test version must be valid: {error}"),
        };
        assert_eq!(version.as_str(), "1.2.0");
        assert_eq!(String::from(version.clone()), "1.2.0");

        let digest = Digest::of(b"seed");
        assert_eq!(digest.value().len(), 64);
        assert_ne!(digest.value(), "");
        assert_eq!(digest.algorithm(), "sha256");
    }

    /// The identifier length bound holds at its boundary.
    #[test]
    fn the_identifier_length_bound_holds_at_its_boundary() {
        let at_limit = "a".repeat(MAX_IDENTIFIER_LENGTH);
        assert!(
            Identifier::new(&at_limit).is_ok(),
            "an identifier of exactly the limit is accepted"
        );
        // One over and far over: an `==` mutation refuses only the first.
        for excess in [1, 2, MAX_IDENTIFIER_LENGTH] {
            let over = "a".repeat(MAX_IDENTIFIER_LENGTH + excess);
            assert!(
                matches!(Identifier::new(&over), Err(ContractError::TooLong { .. })),
                "an identifier {excess} over the limit must be refused"
            );
        }
    }

    /// Every contract error renders as distinct, non-empty text.
    #[test]
    fn every_contract_error_renders_a_distinct_message() {
        let all = [
            ContractError::Empty,
            ContractError::TooLong {
                maximum: 8,
                actual: 9,
            },
            ContractError::InvalidIdentifierCharacter { index: 3 },
            ContractError::MissingNamespace,
            ContractError::InvalidNamespacedName,
            ContractError::InvalidVersion,
        ];
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for error in all.clone() {
            let rendered = match error {
                // Exhaustive: a variant added later stops compiling here.
                ContractError::Empty
                | ContractError::TooLong { .. }
                | ContractError::InvalidIdentifierCharacter { .. }
                | ContractError::MissingNamespace
                | ContractError::InvalidNamespacedName
                | ContractError::InvalidVersion => error.to_string(),
            };
            assert!(!rendered.is_empty(), "{error:?} renders nothing");
            assert!(seen.insert(rendered), "{error:?} shares another message");
        }
        assert_eq!(seen.len(), all.len());
    }

    /// The normative v1 policy-bundle contract.
    fn bundle_schema() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../policy/schemas/v1/policy-bundle.schema.json"
        );
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => unreachable!("the v1 bundle schema must be readable: {error}"),
        };
        match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => unreachable!("the v1 bundle schema must be valid JSON: {error}"),
        }
    }

    /// Reads an `enum` array out of the schema by JSON pointer.
    fn schema_enum(pointer: &str) -> Vec<String> {
        let schema = bundle_schema();
        let node = match schema.pointer(pointer) {
            Some(node) => node,
            None => unreachable!("schema pointer must resolve: {pointer}"),
        };
        let values = match node.as_array() {
            Some(values) => values,
            None => unreachable!("schema enum must be an array: {pointer}"),
        };
        values
            .iter()
            .map(|value| match value.as_str() {
                Some(text) => text.to_owned(),
                None => unreachable!("schema enum values must be strings: {pointer}"),
            })
            .collect()
    }

    fn wire<T: serde::Serialize>(values: &[T]) -> Vec<String> {
        values
            .iter()
            .map(|value| match serde_json::to_value(value) {
                Ok(serde_json::Value::String(text)) => text,
                other => unreachable!("enum must serialize to a string, got {other:?}"),
            })
            .collect()
    }

    /// The schema is the contract; the Rust vocabulary must match it exactly.
    ///
    /// Compared as sets in both directions, so this fails on a Rust variant the
    /// schema does not admit *and* on a schema value Rust cannot express. A
    /// rename that drifted one side would otherwise surface as a policy rule
    /// that silently stops matching what it used to match, which is a
    /// restriction disappearing.
    #[test]
    fn enum_wire_spellings_match_the_v1_schema() {
        let cases: [(&str, Vec<String>); 5] = [
            (
                "/properties/rules/items/properties/effect/enum",
                wire(&[Restriction::Ask, Restriction::Deny]),
            ),
            (
                "/properties/layer/enum",
                wire(&[
                    ExternalPolicyLayer::Organization,
                    ExternalPolicyLayer::User,
                    ExternalPolicyLayer::Repository,
                ]),
            ),
            (
                "/properties/rules/items/properties/selectors/properties/operation_effects/items/enum",
                wire(&[
                    OperationEffect::Read,
                    OperationEffect::Create,
                    OperationEffect::Update,
                    OperationEffect::Delete,
                    OperationEffect::Move,
                    OperationEffect::Execute,
                    OperationEffect::PermissionChange,
                    OperationEffect::Publish,
                    OperationEffect::UnknownMutation,
                ]),
            ),
            (
                "/properties/rules/items/properties/selectors/properties/reversibility/items/enum",
                wire(&[
                    Reversibility::Reversible,
                    Reversibility::Recoverable,
                    Reversibility::ConditionallyRecoverable,
                    Reversibility::Irreversible,
                    Reversibility::Unknown,
                ]),
            ),
            (
                "/properties/rules/items/properties/selectors/properties/blast_radius/items/enum",
                wire(&[
                    BlastRadius::Single,
                    BlastRadius::Bounded,
                    BlastRadius::Broad,
                    BlastRadius::Unbounded,
                    BlastRadius::Unknown,
                ]),
            ),
        ];

        for (pointer, rust) in cases {
            let mut schema = schema_enum(pointer);
            let mut rust = rust;
            schema.sort();
            rust.sort();
            assert_eq!(schema, rust, "vocabulary drift at {pointer}");
        }

        // The environment vocabulary appears in two places and both must agree.
        let mut environments = wire(&[
            EnvironmentClass::Local,
            EnvironmentClass::Development,
            EnvironmentClass::Test,
            EnvironmentClass::Staging,
            EnvironmentClass::Production,
            EnvironmentClass::Shared,
            EnvironmentClass::Unknown,
        ]);
        environments.sort();
        for pointer in [
            "/properties/scope/properties/environments/items/enum",
            "/properties/rules/items/properties/selectors/properties/environments/items/enum",
        ] {
            let mut schema = schema_enum(pointer);
            schema.sort();
            assert_eq!(schema, environments, "vocabulary drift at {pointer}");
        }
    }

    /// A supplied bundle cannot weaken, and cannot claim to be the baseline.
    ///
    /// Both are unknown-variant rejections rather than validation rules: the
    /// types the deserializer targets cannot represent either value, so there
    /// is no code path that accepts one and then decides what to do with it.
    #[test]
    fn a_supplied_bundle_cannot_express_allow_or_the_builtin_layer() {
        assert!(serde_json::from_str::<Restriction>("\"allow\"").is_err());
        assert!(serde_json::from_str::<ExternalPolicyLayer>("\"builtin\"").is_err());
        // The values it may express still work.
        assert_eq!(
            match serde_json::from_str::<Restriction>("\"deny\"") {
                Ok(value) => value,
                Err(error) => unreachable!("deny must parse: {error}"),
            },
            Restriction::Deny
        );
    }

    /// Deserialization uses the validating constructor, not a bypass.
    #[test]
    fn deserialization_cannot_produce_an_unvalidated_primitive() {
        assert!(serde_json::from_str::<Identifier>("\"has space\"").is_err());
        assert!(serde_json::from_str::<Identifier>("\"\"").is_err());
        assert!(serde_json::from_str::<NamespacedName>("\"Git.status\"").is_err());
        assert!(serde_json::from_str::<NamespacedName>("\"nonamespace\"").is_err());
        assert!(serde_json::from_str::<Version>("\"latest\"").is_err());
        assert!(serde_json::from_str::<Identifier>("\"ok.value\"").is_ok());
    }

    #[test]
    fn identifier_rejects_whitespace() {
        // Byte 8 is the space in "repo/../ escaped". Pinning the index keeps
        // this test honest about *why* the value is rejected: the preceding
        // "../" is accepted, as `identifier_is_not_a_path_type` records.
        assert!(matches!(
            Identifier::new("repo/../ escaped"),
            Err(ContractError::InvalidIdentifierCharacter { index: 8 })
        ));
    }

    /// Behaviour-pinning test, not a security invariant: there is no weakened
    /// implementation this could be red against, because permitting these
    /// characters is the contract.
    ///
    /// The v1 `boundedId` pattern (`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`) admits
    /// `/` and `.`, so an identifier may contain path-shaped text including
    /// traversal segments. That is deliberate: `Identifier` names rules,
    /// bundles, sessions and actors -- never a filesystem target. Path
    /// containment belongs to the platform resolver, which canonicalizes
    /// against a trusted boundary using native APIs.
    ///
    /// Pinned so no later reader mistakes the whitespace rejection above for
    /// traversal rejection, and so that giving `Identifier` a path-typed role
    /// has to break a test that says why it must not.
    #[test]
    fn identifier_is_not_a_path_type() {
        assert!(Identifier::new("repo/../escaped").is_ok());
        assert!(Identifier::new("etc/passwd").is_ok());
        assert!(Identifier::new("../../secrets").is_err()); // leading '.' only
    }

    #[test]
    fn namespaced_name_requires_lowercase_segments() {
        assert!(NamespacedName::new("git.force_update").is_ok());
        assert!(matches!(
            NamespacedName::new("Git.force_update"),
            Err(ContractError::InvalidNamespacedName)
        ));
        assert!(matches!(
            NamespacedName::new("delete"),
            Err(ContractError::MissingNamespace)
        ));
    }

    #[test]
    fn version_matches_contract_syntax() {
        assert!(Version::new("1.0.0+build.7").is_ok());
        assert!(Version::new("1.0.0-rc.1").is_ok());
        assert!(matches!(
            Version::new("1.0.0.1"),
            Err(ContractError::InvalidVersion)
        ));
        assert!(matches!(
            Version::new("latest"),
            Err(ContractError::InvalidVersion)
        ));
    }
}
