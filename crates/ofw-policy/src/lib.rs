#![forbid(unsafe_code)]

mod bundle;

pub use bundle::{BundleError, MAX_BUNDLE_BYTES, SUPPORTED_SCHEMA_VERSION, parse_bundle};

use std::collections::BTreeSet;

use ofw_contracts::{
    BlastRadius, EnvironmentClass, Identifier, NamespacedName, OperationEffect, PolicyLayer,
    Restriction, Reversibility, Version,
};

const MAX_RULES_PER_BUNDLE: usize = 2_048;
const MAX_SELECTOR_VALUES: usize = 64;
const MAX_TARGET_KINDS: usize = 256;

/// Composition-wide bounds. `MAX_RULES_PER_BUNDLE` bounds one bundle; without
/// these, an unbounded bundle count makes an effective policy unbounded, and
/// evaluation is linear in the effective rule count under a caller deadline.
const MAX_BUNDLES: usize = 32;
const MAX_EFFECTIVE_RULES: usize = 8_192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Fact<T> {
    Known(T),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationFacts {
    operation_kind: Fact<NamespacedName>,
    operation_effect: Fact<OperationEffect>,
    target_kinds: Fact<BTreeSet<NamespacedName>>,
    environment: Fact<EnvironmentClass>,
    reversibility: Fact<Reversibility>,
    blast_radius: Fact<BlastRadius>,
}

impl OperationFacts {
    pub fn new(
        operation_kind: Fact<NamespacedName>,
        operation_effect: Fact<OperationEffect>,
        target_kinds: Fact<BTreeSet<NamespacedName>>,
        environment: Fact<EnvironmentClass>,
        reversibility: Fact<Reversibility>,
        blast_radius: Fact<BlastRadius>,
    ) -> Result<Self, PolicyError> {
        if matches!(&target_kinds, Fact::Known(kinds) if kinds.len() > MAX_TARGET_KINDS) {
            return Err(PolicyError::TooManyTargetKinds);
        }
        Ok(Self {
            operation_kind,
            operation_effect,
            target_kinds,
            environment,
            reversibility,
            blast_radius,
        })
    }

    #[must_use]
    pub fn with_unknown_operation_kind(mut self) -> Self {
        self.operation_kind = Fact::Unknown;
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Selectors {
    operation_kinds: BTreeSet<NamespacedName>,
    operation_effects: BTreeSet<OperationEffect>,
    target_kinds: BTreeSet<NamespacedName>,
    environments: BTreeSet<EnvironmentClass>,
    reversibility: BTreeSet<Reversibility>,
    blast_radius: BTreeSet<BlastRadius>,
    canonical_path_prefixes: BTreeSet<String>,
}

impl Selectors {
    #[must_use]
    pub fn for_operation_kind(operation_kind: NamespacedName) -> Self {
        Self {
            operation_kinds: BTreeSet::from([operation_kind]),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_operation_kinds(
        mut self,
        operation_kinds: impl IntoIterator<Item = NamespacedName>,
    ) -> Self {
        self.operation_kinds.extend(operation_kinds);
        self
    }

    #[must_use]
    pub fn with_operation_effects(
        mut self,
        effects: impl IntoIterator<Item = OperationEffect>,
    ) -> Self {
        self.operation_effects.extend(effects);
        self
    }

    #[must_use]
    pub fn with_target_kinds(mut self, kinds: impl IntoIterator<Item = NamespacedName>) -> Self {
        self.target_kinds.extend(kinds);
        self
    }

    #[must_use]
    pub fn with_environments(
        mut self,
        environments: impl IntoIterator<Item = EnvironmentClass>,
    ) -> Self {
        self.environments.extend(environments);
        self
    }

    #[must_use]
    pub fn with_reversibility(mut self, values: impl IntoIterator<Item = Reversibility>) -> Self {
        self.reversibility.extend(values);
        self
    }

    #[must_use]
    pub fn with_blast_radius(mut self, values: impl IntoIterator<Item = BlastRadius>) -> Self {
        self.blast_radius.extend(values);
        self
    }

    pub fn with_canonical_path_prefixes(
        mut self,
        prefixes: impl IntoIterator<Item = String>,
    ) -> Result<Self, PolicyError> {
        for prefix in prefixes {
            if prefix.is_empty() || prefix.len() > 4_096 {
                return Err(PolicyError::InvalidCanonicalPathPrefix);
            }
            self.canonical_path_prefixes.insert(prefix);
        }
        if self.canonical_path_prefixes.len() > 64 {
            return Err(PolicyError::TooManyCanonicalPathPrefixes);
        }
        Ok(self)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operation_kinds.is_empty()
            && self.operation_effects.is_empty()
            && self.target_kinds.is_empty()
            && self.environments.is_empty()
            && self.reversibility.is_empty()
            && self.blast_radius.is_empty()
            && self.canonical_path_prefixes.is_empty()
    }

    fn applicability(&self, facts: &OperationFacts) -> RuleApplicability {
        let mut missing = BTreeSet::new();

        if !matches_scalar(
            &self.operation_kinds,
            &facts.operation_kind,
            MissingFact::OperationKind,
            &mut missing,
        ) || !matches_scalar(
            &self.operation_effects,
            &facts.operation_effect,
            MissingFact::OperationEffect,
            &mut missing,
        ) || !matches_set(
            &self.target_kinds,
            &facts.target_kinds,
            MissingFact::TargetKinds,
            &mut missing,
        ) || !matches_scalar(
            &self.environments,
            &facts.environment,
            MissingFact::Environment,
            &mut missing,
        ) || !matches_scalar(
            &self.reversibility,
            &facts.reversibility,
            MissingFact::Reversibility,
            &mut missing,
        ) || !matches_scalar(
            &self.blast_radius,
            &facts.blast_radius,
            MissingFact::BlastRadius,
            &mut missing,
        ) {
            return RuleApplicability::NoMatch;
        }

        if !self.canonical_path_prefixes.is_empty() {
            missing.insert(MissingFact::CanonicalPathResolution);
        }

        if missing.is_empty() {
            RuleApplicability::Match
        } else {
            RuleApplicability::Indeterminate(missing)
        }
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.is_empty() {
            return Err(PolicyError::EmptySelectors);
        }
        if self.operation_kinds.len() > MAX_SELECTOR_VALUES
            || self.target_kinds.len() > MAX_SELECTOR_VALUES
        {
            return Err(PolicyError::TooManySelectorValues);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictionRule {
    pub rule_id: Identifier,
    pub restriction: Restriction,
    pub selectors: Selectors,
    pub risk_categories: BTreeSet<NamespacedName>,
    pub rationale: String,
    pub safer_alternatives: Vec<String>,
}

impl RestrictionRule {
    pub fn new(
        rule_id: Identifier,
        restriction: Restriction,
        selectors: Selectors,
        risk_categories: BTreeSet<NamespacedName>,
        rationale: impl Into<String>,
        safer_alternatives: Vec<String>,
    ) -> Result<Self, PolicyError> {
        let rationale = rationale.into();
        selectors.validate()?;
        if risk_categories.is_empty() || risk_categories.len() > 64 {
            return Err(PolicyError::InvalidRiskCategories);
        }
        if rationale.is_empty() || rationale.len() > 512 {
            return Err(PolicyError::InvalidRationale);
        }
        if safer_alternatives.len() > 8
            || safer_alternatives
                .iter()
                .any(|value| value.is_empty() || value.len() > 512)
        {
            return Err(PolicyError::InvalidSaferAlternatives);
        }
        Ok(Self {
            rule_id,
            restriction,
            selectors,
            risk_categories,
            rationale,
            safer_alternatives,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPolicyBundle {
    layer: PolicyLayer,
    bundle_id: Identifier,
    bundle_version: Version,
    rules: Vec<RestrictionRule>,
}

impl ValidatedPolicyBundle {
    pub fn new(
        layer: PolicyLayer,
        bundle_id: Identifier,
        bundle_version: Version,
        mut rules: Vec<RestrictionRule>,
    ) -> Result<Self, PolicyError> {
        if !layer.is_external() {
            return Err(PolicyError::BuiltinLayerNotExternalPolicy);
        }
        if rules.len() > MAX_RULES_PER_BUNDLE {
            return Err(PolicyError::TooManyRules);
        }
        rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        if rules
            .windows(2)
            .any(|pair| pair[0].rule_id == pair[1].rule_id)
        {
            return Err(PolicyError::DuplicateRuleIdentity);
        }
        Ok(Self {
            layer,
            bundle_id,
            bundle_version,
            rules,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EffectiveRuleIdentity {
    pub layer: PolicyLayer,
    pub bundle_id: Identifier,
    pub bundle_version: Version,
    pub rule_id: Identifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectiveRule {
    identity: EffectiveRuleIdentity,
    rule: RestrictionRule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePolicy {
    rules: Vec<EffectiveRule>,
}

impl EffectivePolicy {
    pub fn compose(
        bundles: impl IntoIterator<Item = ValidatedPolicyBundle>,
    ) -> Result<Self, PolicyError> {
        let mut rules = Vec::new();
        let mut bundle_identities = BTreeSet::new();
        for bundle in bundles {
            let bundle_identity = (
                bundle.layer,
                bundle.bundle_id.clone(),
                bundle.bundle_version.clone(),
            );
            if !bundle_identities.insert(bundle_identity) {
                return Err(PolicyError::DuplicateBundleIdentity);
            }
            if bundle_identities.len() > MAX_BUNDLES {
                return Err(PolicyError::TooManyBundles);
            }
            for rule in bundle.rules {
                if rules.len() >= MAX_EFFECTIVE_RULES {
                    return Err(PolicyError::TooManyEffectiveRules);
                }
                rules.push(EffectiveRule {
                    identity: EffectiveRuleIdentity {
                        layer: bundle.layer,
                        bundle_id: bundle.bundle_id.clone(),
                        bundle_version: bundle.bundle_version.clone(),
                        rule_id: rule.rule_id.clone(),
                    },
                    rule,
                });
            }
        }
        rules.sort_by(|left, right| left.identity.cmp(&right.identity));
        if rules
            .windows(2)
            .any(|pair| pair[0].identity == pair[1].identity)
        {
            return Err(PolicyError::DuplicateEffectiveRuleIdentity);
        }
        Ok(Self { rules })
    }

    #[must_use]
    pub fn rule_identities(&self) -> Vec<EffectiveRuleIdentity> {
        self.rules
            .iter()
            .map(|rule| rule.identity.clone())
            .collect()
    }

    #[must_use]
    pub fn evaluate(&self, facts: &OperationFacts) -> PolicyEvaluation {
        let mut ask_rules = Vec::new();
        let mut deny_rules = Vec::new();
        let mut indeterminate_rules = Vec::new();
        let mut missing_facts = BTreeSet::new();

        for effective_rule in &self.rules {
            match effective_rule.rule.selectors.applicability(facts) {
                RuleApplicability::NoMatch => {}
                RuleApplicability::Match => match effective_rule.rule.restriction {
                    Restriction::Ask => ask_rules.push(effective_rule.identity.clone()),
                    Restriction::Deny => deny_rules.push(effective_rule.identity.clone()),
                },
                RuleApplicability::Indeterminate(missing) => {
                    missing_facts.extend(missing);
                    indeterminate_rules.push(effective_rule.identity.clone());
                }
            }
        }

        if !deny_rules.is_empty() {
            PolicyEvaluation {
                outcome: PolicyOutcome::Deny,
                determining_rules: deny_rules,
                indeterminate_rules,
                missing_facts,
            }
        } else if !missing_facts.is_empty() {
            PolicyEvaluation {
                outcome: PolicyOutcome::Indeterminate,
                determining_rules: Vec::new(),
                indeterminate_rules,
                missing_facts,
            }
        } else if !ask_rules.is_empty() {
            PolicyEvaluation {
                outcome: PolicyOutcome::Ask,
                determining_rules: ask_rules,
                indeterminate_rules,
                missing_facts,
            }
        } else {
            PolicyEvaluation {
                outcome: PolicyOutcome::NoRestriction,
                determining_rules: Vec::new(),
                indeterminate_rules,
                missing_facts,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyOutcome {
    /// No policy rule restricted this operation.
    ///
    /// This is **not** an authorization and must never be mapped to allow. It
    /// means only that policy added nothing, which is also true of every
    /// operation the system does not understand. A final allow additionally
    /// requires a built-in supported-operation proof; compose the two with
    /// `ofw_core::decide` rather than reading this variant directly.
    NoRestriction,
    Ask,
    Indeterminate,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    pub outcome: PolicyOutcome,
    /// Rules at the winning restriction level, per the v1 decision contract.
    /// An `Indeterminate` outcome has no determining rule: the contract's
    /// `effect` enum admits only `allow`, `ask`, and `deny`, so listing an
    /// unresolved rule here would misreport it as having determined one.
    pub determining_rules: Vec<EffectiveRuleIdentity>,
    /// Diagnostics: rules that could not be decided because a selector needed
    /// a fact that was unavailable. `contracts-v1.md` allows diagnostics to
    /// list non-determining matches separately. Without this, an operator sees
    /// only which *fact* was missing and cannot tell which rule required it.
    pub indeterminate_rules: Vec<EffectiveRuleIdentity>,
    pub missing_facts: BTreeSet<MissingFact>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MissingFact {
    OperationKind,
    OperationEffect,
    TargetKinds,
    Environment,
    Reversibility,
    BlastRadius,
    CanonicalPathResolution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuleApplicability {
    Match,
    NoMatch,
    Indeterminate(BTreeSet<MissingFact>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    BuiltinLayerNotExternalPolicy,
    DuplicateBundleIdentity,
    DuplicateEffectiveRuleIdentity,
    DuplicateRuleIdentity,
    EmptySelectors,
    InvalidCanonicalPathPrefix,
    InvalidRationale,
    InvalidRiskCategories,
    InvalidSaferAlternatives,
    TooManyBundles,
    TooManyCanonicalPathPrefixes,
    TooManyEffectiveRules,
    TooManyRules,
    TooManySelectorValues,
    TooManyTargetKinds,
}

fn matches_scalar<T: Ord>(
    selectors: &BTreeSet<T>,
    fact: &Fact<T>,
    missing_fact: MissingFact,
    missing: &mut BTreeSet<MissingFact>,
) -> bool {
    if selectors.is_empty() {
        return true;
    }
    match fact {
        Fact::Known(value) => selectors.contains(value),
        Fact::Unknown => {
            missing.insert(missing_fact);
            true
        }
    }
}

fn matches_set<T: Ord>(
    selectors: &BTreeSet<T>,
    fact: &Fact<BTreeSet<T>>,
    missing_fact: MissingFact,
    missing: &mut BTreeSet<MissingFact>,
) -> bool {
    if selectors.is_empty() {
        return true;
    }
    match fact {
        Fact::Known(values) => !selectors.is_disjoint(values),
        Fact::Unknown => {
            missing.insert(missing_fact);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ofw_contracts::{
        BlastRadius, EnvironmentClass, Identifier, NamespacedName, OperationEffect, PolicyLayer,
        Restriction, Reversibility, Version,
    };

    use super::{
        EffectivePolicy, EffectiveRuleIdentity, Fact, MAX_BUNDLES, MAX_EFFECTIVE_RULES,
        MAX_RULES_PER_BUNDLE, MAX_SELECTOR_VALUES, OperationFacts, PolicyError, PolicyEvaluation,
        PolicyOutcome, RestrictionRule, Selectors, ValidatedPolicyBundle,
    };

    fn identifier(value: &str) -> Identifier {
        match Identifier::new(value) {
            Ok(identifier) => identifier,
            Err(error) => unreachable!("test identifier must be valid: {error}"),
        }
    }

    fn name(value: &str) -> NamespacedName {
        match NamespacedName::new(value) {
            Ok(name) => name,
            Err(error) => unreachable!("test name must be valid: {error}"),
        }
    }

    fn version(value: &str) -> Version {
        match Version::new(value) {
            Ok(version) => version,
            Err(error) => unreachable!("test version must be valid: {error}"),
        }
    }

    fn complete_facts() -> OperationFacts {
        match OperationFacts::new(
            Fact::Known(name("git.force_update")),
            Fact::Known(OperationEffect::Update),
            Fact::Known(BTreeSet::from([name("git.repository")])),
            Fact::Known(EnvironmentClass::Local),
            Fact::Known(Reversibility::ConditionallyRecoverable),
            Fact::Known(BlastRadius::Single),
        ) {
            Ok(facts) => facts,
            Err(error) => unreachable!("test facts must be valid: {error:?}"),
        }
    }

    fn rule(rule_id: &str, restriction: Restriction) -> RestrictionRule {
        match RestrictionRule::new(
            identifier(rule_id),
            restriction,
            Selectors::for_operation_kind(name("git.force_update")),
            BTreeSet::from([name("git.history_loss")]),
            "Protect Git history.",
            vec!["Create a new branch instead.".to_owned()],
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        }
    }

    fn bundle(
        layer: PolicyLayer,
        bundle_id: &str,
        rules: Vec<RestrictionRule>,
    ) -> ValidatedPolicyBundle {
        match ValidatedPolicyBundle::new(layer, identifier(bundle_id), version("1.0.0"), rules) {
            Ok(bundle) => bundle,
            Err(error) => unreachable!("test bundle must be valid: {error:?}"),
        }
    }

    fn policy(bundles: Vec<ValidatedPolicyBundle>) -> EffectivePolicy {
        match EffectivePolicy::compose(bundles) {
            Ok(policy) => policy,
            Err(error) => unreachable!("test policy must be valid: {error:?}"),
        }
    }

    /// The outcome of a single deny rule carrying exactly these selectors.
    fn outcome_for(selectors: Selectors) -> PolicyOutcome {
        let scoped = match RestrictionRule::new(
            identifier("scoped"),
            Restriction::Deny,
            selectors,
            BTreeSet::from([name("policy.scope")]),
            "Scoped to one dimension.",
            Vec::new(),
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        };
        policy(vec![bundle(
            PolicyLayer::Organization,
            "org.scoped",
            vec![scoped],
        )])
        .evaluate(&complete_facts())
        .outcome
    }

    #[test]
    fn repository_ask_cannot_narrow_organization_deny() {
        let effective = policy(vec![
            bundle(
                PolicyLayer::Organization,
                "org.baseline",
                vec![rule("deny-force-update", Restriction::Deny)],
            ),
            bundle(
                PolicyLayer::Repository,
                "repo.local",
                vec![rule("ask-force-update", Restriction::Ask)],
            ),
        ]);

        assert_eq!(
            effective.evaluate(&complete_facts()).outcome,
            PolicyOutcome::Deny
        );
    }

    #[test]
    fn composition_order_is_non_semantic() {
        let forward = policy(vec![
            bundle(
                PolicyLayer::Organization,
                "org.baseline",
                vec![rule("deny-force-update", Restriction::Deny)],
            ),
            bundle(
                PolicyLayer::User,
                "user.local",
                vec![rule("ask-force-update", Restriction::Ask)],
            ),
        ]);
        let reverse = policy(vec![
            bundle(
                PolicyLayer::User,
                "user.local",
                vec![rule("ask-force-update", Restriction::Ask)],
            ),
            bundle(
                PolicyLayer::Organization,
                "org.baseline",
                vec![rule("deny-force-update", Restriction::Deny)],
            ),
        ]);

        assert_eq!(forward.rule_identities(), reverse.rule_identities());
        assert_eq!(
            forward.evaluate(&complete_facts()),
            reverse.evaluate(&complete_facts())
        );
    }

    #[test]
    fn duplicate_effective_identity_is_rejected() {
        let duplicate = bundle(
            PolicyLayer::Organization,
            "org.baseline",
            vec![rule("deny-force-update", Restriction::Deny)],
        );
        let result = EffectivePolicy::compose([duplicate.clone(), duplicate]);
        assert!(matches!(result, Err(PolicyError::DuplicateBundleIdentity)));
    }

    #[test]
    fn unavailable_applicability_fact_is_indeterminate() {
        let effective = policy(vec![bundle(
            PolicyLayer::Organization,
            "org.baseline",
            vec![rule("deny-force-update", Restriction::Deny)],
        )]);
        let facts = complete_facts().with_unknown_operation_kind();

        assert_eq!(
            effective.evaluate(&facts).outcome,
            PolicyOutcome::Indeterminate
        );
    }

    #[test]
    fn unresolved_canonical_path_selector_is_indeterminate() {
        let selectors = match Selectors::for_operation_kind(name("git.force_update"))
            .with_canonical_path_prefixes(["F:/protected".to_owned()])
        {
            Ok(selectors) => selectors,
            Err(error) => unreachable!("test selectors must be valid: {error:?}"),
        };
        let protected_rule = match RestrictionRule::new(
            identifier("protect-path"),
            Restriction::Deny,
            selectors,
            BTreeSet::from([name("filesystem.protected_path")]),
            "Protect the canonical path.",
            Vec::new(),
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        };
        let effective = policy(vec![bundle(
            PolicyLayer::Organization,
            "org.paths",
            vec![protected_rule],
        )]);

        assert_eq!(
            effective.evaluate(&complete_facts()).outcome,
            PolicyOutcome::Indeterminate
        );
    }

    #[test]
    fn matched_deny_dominates_an_indeterminate_rule() {
        let path_selectors = match Selectors::for_operation_kind(name("git.force_update"))
            .with_canonical_path_prefixes(["F:/protected".to_owned()])
        {
            Ok(selectors) => selectors,
            Err(error) => unreachable!("test selectors must be valid: {error:?}"),
        };
        let unresolved_path_rule = match RestrictionRule::new(
            identifier("protect-path"),
            Restriction::Ask,
            path_selectors,
            BTreeSet::from([name("filesystem.protected_path")]),
            "Protect the canonical path.",
            Vec::new(),
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        };
        let effective = policy(vec![bundle(
            PolicyLayer::Organization,
            "org.combined",
            vec![
                rule("deny-force-update", Restriction::Deny),
                unresolved_path_rule,
            ],
        )]);

        assert_eq!(
            effective.evaluate(&complete_facts()).outcome,
            PolicyOutcome::Deny
        );
    }

    #[test]
    fn known_non_match_overrides_an_irrelevant_unknown_dimension() {
        let selectors = Selectors::for_operation_kind(name("git.force_update"))
            .with_operation_effects([OperationEffect::Delete]);
        let delete_only_rule = match RestrictionRule::new(
            identifier("deny-delete"),
            Restriction::Deny,
            selectors,
            BTreeSet::from([name("data.destructive")]),
            "Deny deletion only.",
            Vec::new(),
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        };
        let effective = policy(vec![bundle(
            PolicyLayer::Organization,
            "org.delete-only",
            vec![delete_only_rule],
        )]);
        let facts = complete_facts().with_unknown_operation_kind();

        assert_eq!(
            effective.evaluate(&facts).outcome,
            PolicyOutcome::NoRestriction
        );
    }

    /// Each selector dimension narrows a rule on its own.
    ///
    /// Nine mutants survived a mutation run all saying the same thing: nothing
    /// asserted that a rule scoped by `target_kinds`, `environments`,
    /// `reversibility` or `blast_radius` *fails* to match facts outside its
    /// scope. Those dimensions were built and composed in tests, but replacing
    /// a builder with a no-op, or one of `applicability`'s `||` with `&&`,
    /// changed no result any test could see. `operation_kinds` and
    /// `operation_effects` were already covered, which is why their equivalents
    /// died and these did not.
    ///
    /// The direction is worth naming. All but one of the nine make a rule apply
    /// *more* widely -- a production-scoped deny firing in a local repository
    /// -- which produces extra denies rather than extra allows. That is the
    /// safe direction and it is still a defect: a rule that does not mean what
    /// it says is a rule nobody can reason about. The exception is dropping the
    /// negation inside `matches_set`, which would stop a rule scoped to a
    /// target kind from applying to that kind at all.
    #[test]
    fn each_selector_dimension_narrows_on_its_own() {
        // Each pair selects, and then declines to select, the corresponding
        // value in `complete_facts`.
        let dimensions = [
            (
                "operation kind",
                Selectors::default().with_operation_kinds([name("git.force_update")]),
                Selectors::default().with_operation_kinds([name("git.push")]),
            ),
            (
                "operation effect",
                Selectors::default().with_operation_effects([OperationEffect::Update]),
                Selectors::default().with_operation_effects([OperationEffect::Delete]),
            ),
            (
                "target kind",
                Selectors::default().with_target_kinds([name("git.repository")]),
                Selectors::default().with_target_kinds([name("git.worktree_path")]),
            ),
            (
                "environment",
                Selectors::default().with_environments([EnvironmentClass::Local]),
                Selectors::default().with_environments([EnvironmentClass::Production]),
            ),
            (
                "reversibility",
                Selectors::default().with_reversibility([Reversibility::ConditionallyRecoverable]),
                Selectors::default().with_reversibility([Reversibility::Irreversible]),
            ),
            (
                "blast radius",
                Selectors::default().with_blast_radius([BlastRadius::Single]),
                Selectors::default().with_blast_radius([BlastRadius::Broad]),
            ),
        ];

        for (dimension, matching, non_matching) in dimensions {
            assert_eq!(
                outcome_for(matching),
                PolicyOutcome::Deny,
                "a rule selecting the {dimension} of the facts must apply"
            );
            assert_eq!(
                outcome_for(non_matching),
                PolicyOutcome::NoRestriction,
                "a rule selecting a different {dimension} must not apply"
            );
        }
    }

    /// A rule that selects nothing selects everything, and is refused.
    ///
    /// `is_empty` is the whole of what stands between an unscoped rule and a
    /// policy where one rule silently governs every operation. Broader than
    /// intended, so more denies rather than more allows -- and still not a rule
    /// its author could have meant to write.
    #[test]
    fn a_rule_that_selects_nothing_is_rejected() {
        assert!(Selectors::default().is_empty());
        assert!(!Selectors::for_operation_kind(name("git.force_update")).is_empty());

        let unscoped = RestrictionRule::new(
            identifier("selects-everything"),
            Restriction::Deny,
            Selectors::default(),
            BTreeSet::from([name("policy.scope")]),
            "A rule with no selectors at all.",
            Vec::new(),
        );
        assert!(matches!(unscoped, Err(PolicyError::EmptySelectors)));
    }

    /// The effective policy can name every rule it holds.
    ///
    /// This list is what an audit record uses to say which rules were in force
    /// for a decision. An empty one changes no outcome and leaves the record
    /// unable to say what governed it, which is the difference between an audit
    /// trail and a log line.
    #[test]
    fn the_effective_policy_names_every_rule_it_holds() {
        let effective = policy(vec![
            bundle(
                PolicyLayer::Organization,
                "org.baseline",
                vec![rule("deny-force-update", Restriction::Deny)],
            ),
            bundle(
                PolicyLayer::Repository,
                "repo.local",
                vec![rule("ask-force-update", Restriction::Ask)],
            ),
        ]);

        let identities = effective.rule_identities();
        assert_eq!(identities.len(), 2);
        for (layer, rule_id) in [
            (PolicyLayer::Organization, "deny-force-update"),
            (PolicyLayer::Repository, "ask-force-update"),
        ] {
            assert!(
                identities
                    .iter()
                    .any(|identity| identity.layer == layer
                        && identity.rule_id == identifier(rule_id)),
                "{rule_id} must be named"
            );
        }
    }

    /// The canonical-path-prefix bounds are enforced at their boundaries.
    ///
    /// An empty prefix is a prefix of every path, so a rule carrying one is not
    /// the rule its author wrote -- which is why emptiness and length are
    /// checked with `||` rather than treated as one condition.
    #[test]
    fn the_canonical_path_prefix_bounds_hold_at_their_boundaries() {
        // Both limits are written as literals in the builder rather than named
        // constants, so they are repeated here rather than imported.
        const LONGEST_PREFIX: usize = 4_096;
        const MOST_PREFIXES: usize = 64;
        let base = || Selectors::for_operation_kind(name("git.force_update"));

        assert!(matches!(
            base().with_canonical_path_prefixes([String::new()]),
            Err(PolicyError::InvalidCanonicalPathPrefix)
        ));

        assert!(
            base()
                .with_canonical_path_prefixes(["a".repeat(LONGEST_PREFIX)])
                .is_ok(),
            "a prefix of exactly the limit is accepted"
        );
        // One over and far over: an `==` mutation refuses only the first of
        // these and leaves every longer prefix unbounded.
        for excess in [1, 2, LONGEST_PREFIX] {
            assert!(
                matches!(
                    base().with_canonical_path_prefixes(["a".repeat(LONGEST_PREFIX + excess)]),
                    Err(PolicyError::InvalidCanonicalPathPrefix)
                ),
                "a prefix {excess} bytes over the limit must be refused"
            );
        }

        let prefixes = |count: usize| (0..count).map(|index| format!("/repo/path{index}"));
        assert!(
            base()
                .with_canonical_path_prefixes(prefixes(MOST_PREFIXES))
                .is_ok(),
            "exactly the limit is accepted"
        );
        for excess in [1, 2, MOST_PREFIXES] {
            assert!(
                matches!(
                    base().with_canonical_path_prefixes(prefixes(MOST_PREFIXES + excess)),
                    Err(PolicyError::TooManyCanonicalPathPrefixes)
                ),
                "{excess} prefixes over the limit must be refused"
            );
        }
    }

    #[test]
    fn selector_and_target_fact_bounds_are_enforced() {
        let excessive_selector_values = (0..=64).map(|index| name(&format!("target.kind{index}")));
        let selectors = Selectors::for_operation_kind(name("git.force_update"))
            .with_target_kinds(excessive_selector_values);
        let rule_result = RestrictionRule::new(
            identifier("too-many-selectors"),
            Restriction::Deny,
            selectors,
            BTreeSet::from([name("policy.resource_exhaustion")]),
            "Reject an oversized selector set.",
            Vec::new(),
        );
        assert!(matches!(
            rule_result,
            Err(PolicyError::TooManySelectorValues)
        ));

        // Both selector dimensions the bound covers, pinned from below and from
        // far above. Only the one-over case existed, and an `==` mutation still
        // rejects exactly that while letting every larger set through -- the
        // check stops being a bound while the test that names it still passes.
        let bounded = |kinds: usize, targets: usize| {
            RestrictionRule::new(
                identifier("bounded-selectors"),
                Restriction::Deny,
                Selectors::default()
                    .with_operation_kinds((0..kinds).map(|index| name(&format!("git.kind{index}"))))
                    .with_target_kinds(
                        (0..targets).map(|index| name(&format!("target.kind{index}"))),
                    ),
                BTreeSet::from([name("policy.resource_exhaustion")]),
                "Bounded selector sets.",
                Vec::new(),
            )
        };
        assert!(
            bounded(MAX_SELECTOR_VALUES, MAX_SELECTOR_VALUES).is_ok(),
            "exactly the limit on both dimensions is accepted"
        );
        for excess in [1, 2, MAX_SELECTOR_VALUES] {
            for (kinds, targets) in [
                (MAX_SELECTOR_VALUES + excess, MAX_SELECTOR_VALUES),
                (MAX_SELECTOR_VALUES, MAX_SELECTOR_VALUES + excess),
            ] {
                assert!(
                    matches!(
                        bounded(kinds, targets),
                        Err(PolicyError::TooManySelectorValues)
                    ),
                    "{kinds} kinds and {targets} target kinds must be refused"
                );
            }
        }

        let excessive_target_kinds = (0..=256)
            .map(|index| name(&format!("target.kind{index}")))
            .collect();
        let facts_result = OperationFacts::new(
            Fact::Known(name("git.force_update")),
            Fact::Known(OperationEffect::Update),
            Fact::Known(excessive_target_kinds),
            Fact::Known(EnvironmentClass::Local),
            Fact::Known(Reversibility::ConditionallyRecoverable),
            Fact::Known(BlastRadius::Single),
        );
        assert!(matches!(facts_result, Err(PolicyError::TooManyTargetKinds)));
    }

    #[test]
    fn bundle_rejects_duplicate_rules_and_builtin_layer() {
        let duplicate_rules = ValidatedPolicyBundle::new(
            PolicyLayer::Organization,
            identifier("org.duplicates"),
            version("1.0.0"),
            vec![
                rule("duplicate", Restriction::Ask),
                rule("duplicate", Restriction::Deny),
            ],
        );
        assert!(matches!(
            duplicate_rules,
            Err(PolicyError::DuplicateRuleIdentity)
        ));

        let builtin_bundle = ValidatedPolicyBundle::new(
            PolicyLayer::Builtin,
            identifier("builtin.invalid"),
            version("1.0.0"),
            Vec::new(),
        );
        assert!(matches!(
            builtin_bundle,
            Err(PolicyError::BuiltinLayerNotExternalPolicy)
        ));
    }

    #[test]
    fn adding_restrictions_never_reduces_complete_fact_outcome() {
        let candidates = [Restriction::Ask, Restriction::Deny, Restriction::Ask];
        for base_mask in 0_u8..(1 << candidates.len()) {
            for added_mask in 0_u8..(1 << candidates.len()) {
                if base_mask & added_mask != 0 {
                    continue;
                }
                let base = policy_from_mask(&candidates, base_mask);
                let expanded = policy_from_mask(&candidates, base_mask | added_mask);
                assert!(
                    outcome_rank(expanded.evaluate(&complete_facts()).outcome)
                        >= outcome_rank(base.evaluate(&complete_facts()).outcome)
                );
            }
        }
    }

    #[test]
    fn red_first_witness_detects_last_writer_wins_vulnerability() {
        let invariant = |evaluator: fn(&[Restriction]) -> Restriction| {
            let baseline = evaluator(&[Restriction::Deny]);
            let expanded = evaluator(&[Restriction::Deny, Restriction::Ask]);
            expanded >= baseline
        };

        assert!(!invariant(vulnerable_last_writer_wins));
        assert!(invariant(restriction_union));
    }

    #[test]
    fn red_first_witness_detects_inverted_restriction_ordering() {
        // Every "more restrictive" comparison in this crate and its tests
        // resolves through `Restriction`'s derived `Ord`, which follows
        // declaration order. `red_first_witness_detects_last_writer_wins_
        // vulnerability` cannot catch a reordering, because both sides of its
        // `>=` invert together. Pin the ordering directly instead.
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        enum InvertedRestriction {
            Deny,
            Ask,
        }

        fn most_restrictive<T: Copy + Ord>(values: &[T], fallback: T) -> T {
            values.iter().copied().max().unwrap_or(fallback)
        }

        // Under the real ordering a deny in the set wins.
        assert_eq!(
            most_restrictive(&[Restriction::Deny, Restriction::Ask], Restriction::Ask),
            Restriction::Deny
        );
        // The retained inverted witness silently returns the weaker value from
        // the identical union.
        assert_eq!(
            most_restrictive(
                &[InvertedRestriction::Deny, InvertedRestriction::Ask],
                InvertedRestriction::Ask
            ),
            InvertedRestriction::Ask
        );
        assert!(Restriction::Ask < Restriction::Deny);
    }

    // The two composition bounds are asserted in separate tests on purpose.
    // Combined, the bundle-count assertion aborts the test before the
    // rule-count assertion is reached, so a weakened build could only ever
    // prove the first guard load-bearing. Split, each guard has its own
    // independent red-first evidence.

    #[test]
    fn red_first_witness_detects_unbounded_bundle_count() {
        let excess_bundles: Vec<_> = (0..=MAX_BUNDLES)
            .map(|index| {
                bundle(
                    PolicyLayer::Organization,
                    &format!("org.bundle{index}"),
                    vec![rule("deny-force-update", Restriction::Deny)],
                )
            })
            .collect();

        assert!(matches!(
            EffectivePolicy::compose(excess_bundles.clone()),
            Err(PolicyError::TooManyBundles)
        ));
        // The retained unbounded form accepts the same input.
        assert!(vulnerable_unbounded_compose(&excess_bundles).is_ok());

        // Exactly the limit composes. The guard runs inside the loop after each
        // insert, so the count passes through every value on its way up: both
        // mutations of the comparison fire one bundle early and still refuse
        // the over-limit fixture above, looking correct while refusing a policy
        // set the documentation says is acceptable.
        let at_limit: Vec<_> = excess_bundles.into_iter().take(MAX_BUNDLES).collect();
        assert_eq!(at_limit.len(), MAX_BUNDLES);
        assert!(
            EffectivePolicy::compose(at_limit).is_ok(),
            "exactly MAX_BUNDLES bundles compose"
        );
    }

    #[test]
    fn red_first_witness_detects_unbounded_effective_rule_count() {
        // The aggregate rule bound is independent of the per-bundle bound:
        // five bundles of exactly `MAX_RULES_PER_BUNDLE` rules each are
        // individually valid and stay under `MAX_BUNDLES`, yet together
        // exceed `MAX_EFFECTIVE_RULES`.
        let excess_rules: Vec<_> = (0..5)
            .map(|bundle_index| {
                let rules = (0..MAX_RULES_PER_BUNDLE)
                    .map(|rule_index| rule(&format!("rule-{rule_index}"), Restriction::Deny))
                    .collect();
                bundle(
                    PolicyLayer::Organization,
                    &format!("org.big{bundle_index}"),
                    rules,
                )
            })
            .collect();

        // Compile-time guards: if the bounds are ever retuned so that this
        // fixture stops exceeding the aggregate limit, or starts tripping the
        // bundle limit instead, the test must fail to build rather than pass
        // for a reason it does not claim.
        const { assert!(5 * MAX_RULES_PER_BUNDLE > MAX_EFFECTIVE_RULES) };
        const { assert!(5 <= MAX_BUNDLES) };

        assert!(matches!(
            EffectivePolicy::compose(excess_rules.clone()),
            Err(PolicyError::TooManyEffectiveRules)
        ));
        assert!(vulnerable_unbounded_compose(&excess_rules).is_ok());
    }

    #[test]
    fn red_first_witness_detects_discarded_indeterminate_rule_identity() {
        let selectors = match Selectors::for_operation_kind(name("git.force_update"))
            .with_canonical_path_prefixes(["F:/protected".to_owned()])
        {
            Ok(selectors) => selectors,
            Err(error) => unreachable!("test selectors must be valid: {error:?}"),
        };
        let unresolved_rule = match RestrictionRule::new(
            identifier("protect-path"),
            Restriction::Deny,
            selectors,
            BTreeSet::from([name("filesystem.protected_path")]),
            "Protect the canonical path.",
            Vec::new(),
        ) {
            Ok(rule) => rule,
            Err(error) => unreachable!("test rule must be valid: {error:?}"),
        };
        let effective = policy(vec![bundle(
            PolicyLayer::Organization,
            "org.paths",
            vec![unresolved_rule],
        )]);
        let evaluation = effective.evaluate(&complete_facts());

        // The invariant: an indeterminate outcome names the rule that could not
        // be resolved, not merely the fact class that was unavailable.
        let names_the_unresolved_rule = |identities: &[EffectiveRuleIdentity]| {
            identities.len() == 1 && identities[0].rule_id == identifier("protect-path")
        };

        assert_eq!(evaluation.outcome, PolicyOutcome::Indeterminate);
        assert!(names_the_unresolved_rule(&evaluation.indeterminate_rules));
        // The retained pre-fix behaviour recorded the missing fact and dropped
        // the identity, leaving an operator unable to tell which rule blocked.
        assert!(!names_the_unresolved_rule(
            &vulnerable_discards_indeterminate_identities(&evaluation)
        ));

        // `determining_rules` must stay empty: the v1 decision contract's
        // `effect` enum admits only allow/ask/deny, so an unresolved rule
        // listed there would misreport it as having determined a deny.
        assert!(evaluation.determining_rules.is_empty());
    }

    /// Retained red-first witness: composition without the aggregate bounds.
    fn vulnerable_unbounded_compose(
        bundles: &[ValidatedPolicyBundle],
    ) -> Result<usize, PolicyError> {
        let mut total = 0_usize;
        let mut identities = BTreeSet::new();
        for bundle in bundles {
            let identity = (
                bundle.layer,
                bundle.bundle_id.clone(),
                bundle.bundle_version.clone(),
            );
            if !identities.insert(identity) {
                return Err(PolicyError::DuplicateBundleIdentity);
            }
            total += bundle.rules.len();
        }
        Ok(total)
    }

    /// Retained red-first witness: the pre-fix evaluator recorded which fact was
    /// missing but discarded which rule required it.
    fn vulnerable_discards_indeterminate_identities(
        evaluation: &PolicyEvaluation,
    ) -> Vec<EffectiveRuleIdentity> {
        let _ = evaluation;
        Vec::new()
    }

    fn policy_from_mask(candidates: &[Restriction], mask: u8) -> EffectivePolicy {
        let rules = candidates
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(index, restriction)| rule(&format!("rule-{index}"), *restriction))
            .collect();
        policy(vec![bundle(
            PolicyLayer::Organization,
            "org.generated",
            rules,
        )])
    }

    fn vulnerable_last_writer_wins(restrictions: &[Restriction]) -> Restriction {
        restrictions.last().copied().unwrap_or(Restriction::Ask)
    }

    fn restriction_union(restrictions: &[Restriction]) -> Restriction {
        restrictions
            .iter()
            .copied()
            .max()
            .unwrap_or(Restriction::Ask)
    }

    fn outcome_rank(outcome: PolicyOutcome) -> u8 {
        match outcome {
            PolicyOutcome::NoRestriction => 0,
            PolicyOutcome::Ask => 1,
            PolicyOutcome::Indeterminate => 2,
            PolicyOutcome::Deny => 3,
        }
    }
}
