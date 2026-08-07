//! Loading and activating supplied policy.
//!
//! # A policy that failed to load is not an empty policy
//!
//! This is the whole point of the module. "We could not read the restrictions"
//! and "there are no restrictions" are the same observation only to a system
//! that is willing to fail open. An operator who configured a policy location
//! and then had it fail -- a typo, a bad edit, a permissions change, a partial
//! write -- must not silently get the unrestricted behaviour they would have
//! had by configuring nothing at all.
//!
//! So a configured-but-unloadable policy makes activation **unhealthy**, and
//! an unhealthy activation makes every decision `indeterminate`, which denies.
//! `red_first_witness_detects_unloadable_policy_treated_as_empty` retains the
//! alternative and shows it authorising what a loaded deny would have blocked.
//!
//! Configuring no policy location at all is different, and is healthy: policy
//! is restriction-only, so its absence leaves the built-in baseline exactly as
//! it was. Not configuring external policy is a choice; configuring one that
//! does not work is a fault.

use std::path::{Path, PathBuf};

use ofw_policy::{EffectivePolicy, parse_bundle};

use crate::pipeline::{
    POLICY_ACTIVATION_UNHEALTHY, POLICY_BUNDLE_INVALID, POLICY_LOCATION_UNREADABLE,
    POLICY_TOO_MANY_BUNDLES, Reason,
};

/// Compiled bound on how many bundle files one location may contribute.
///
/// Matches `ofw-policy`'s own composition bound. Exceeding it is a refusal
/// rather than a truncation: loading the first 32 of 40 bundles would drop
/// eight bundles' worth of restrictions.
pub const MAX_BUNDLE_FILES: usize = 32;

/// The result of trying to activate supplied policy.
#[derive(Clone, Debug)]
pub enum PolicyActivation {
    Healthy {
        policy: EffectivePolicy,
        bundle_count: usize,
    },
    Unhealthy(Reason),
}

impl PolicyActivation {
    /// The activation for a deployment with no external policy location.
    ///
    /// An empty effective policy restricts nothing, which is correct: the
    /// built-in baseline is unaffected by policy that does not exist.
    #[must_use]
    pub fn none_configured() -> Self {
        match EffectivePolicy::compose(Vec::new()) {
            Ok(policy) => Self::Healthy {
                policy,
                bundle_count: 0,
            },
            // Composing zero bundles cannot fail. If that ever changes, the
            // system is unhealthy rather than unrestricted.
            Err(_) => Self::Unhealthy(POLICY_ACTIVATION_UNHEALTHY),
        }
    }

    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }

    #[must_use]
    pub const fn bundle_count(&self) -> usize {
        match self {
            Self::Healthy { bundle_count, .. } => *bundle_count,
            Self::Unhealthy(_) => 0,
        }
    }
}

/// Loads every bundle in a directory and composes one immutable snapshot.
///
/// Activation is atomic: the snapshot is composed from all bundles or none is
/// produced at all. There is no path that activates a partial policy, because
/// a partial policy is a policy with restrictions missing.
#[must_use]
pub fn activate_from_directory(directory: &Path) -> PolicyActivation {
    let mut paths = match bundle_paths(directory) {
        Ok(paths) => paths,
        Err(reason) => return PolicyActivation::Unhealthy(reason),
    };
    if paths.len() > MAX_BUNDLE_FILES {
        return PolicyActivation::Unhealthy(POLICY_TOO_MANY_BUNDLES);
    }
    // Deterministic order. Composition is order-independent by design, and
    // sorting means a diagnostic naming "the third bundle" means the same
    // thing on every platform.
    paths.sort();

    let mut bundles = Vec::with_capacity(paths.len());
    for path in &paths {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return PolicyActivation::Unhealthy(POLICY_LOCATION_UNREADABLE),
        };
        match parse_bundle(&bytes) {
            Ok(bundle) => bundles.push(bundle),
            // The reason is deliberately not derived from the bundle error's
            // detail: a policy file's content must not reach a diagnostic.
            Err(_) => return PolicyActivation::Unhealthy(POLICY_BUNDLE_INVALID),
        }
    }

    let bundle_count = bundles.len();
    match EffectivePolicy::compose(bundles) {
        Ok(policy) => PolicyActivation::Healthy {
            policy,
            bundle_count,
        },
        Err(_) => PolicyActivation::Unhealthy(POLICY_ACTIVATION_UNHEALTHY),
    }
}

/// Every `.json` file directly inside the location.
///
/// Not recursive: a policy location is an explicit directory of bundles, and
/// walking into subdirectories would make what is loaded depend on layout
/// nobody declared. A location that cannot be listed is unhealthy, not empty.
fn bundle_paths(directory: &Path) -> Result<Vec<PathBuf>, Reason> {
    let entries = std::fs::read_dir(directory).map_err(|_| POLICY_LOCATION_UNREADABLE)?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| POLICY_LOCATION_UNREADABLE)?;
        let path = entry.path();
        let is_bundle = path
            .extension()
            .is_some_and(|extension| extension == "json");
        let is_file = entry
            .file_type()
            .map_err(|_| POLICY_LOCATION_UNREADABLE)?
            .is_file();
        if is_bundle && is_file {
            paths.push(path);
        }
    }
    Ok(paths)
}
