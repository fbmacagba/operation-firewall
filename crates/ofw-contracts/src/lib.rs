#![forbid(unsafe_code)]

use core::fmt;

const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_NAMESPACED_NAME_LENGTH: usize = 128;
const MAX_VERSION_LENGTH: usize = 64;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamespacedName(String);

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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Version(String);

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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PolicyLayer {
    Builtin,
    Organization,
    User,
    Repository,
}

impl PolicyLayer {
    #[must_use]
    pub const fn is_external(self) -> bool {
        !matches!(self, Self::Builtin)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Restriction {
    Ask,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EnvironmentClass {
    Local,
    Development,
    Test,
    Staging,
    Production,
    Shared,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Reversibility {
    Reversible,
    Recoverable,
    ConditionallyRecoverable,
    Irreversible,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    use super::{ContractError, Identifier, NamespacedName, Version};

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
