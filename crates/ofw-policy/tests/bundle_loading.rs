//! Strict v1 policy-bundle loading.
//!
//! These run against `parse_bundle`'s public surface rather than its internals,
//! because what matters is what a bundle file on disk can and cannot make the
//! policy engine do.

use ofw_policy::{BundleError, MAX_BUNDLE_BYTES, parse_bundle};

/// A minimal valid bundle with one deny rule, rendered with substitutions.
fn bundle_with(rules: &str) -> String {
    format!(
        r#"{{
  "schema_version": "1.0",
  "bundle_id": "org.baseline",
  "bundle_version": "1.0.0",
  "layer": "organization",
  "issued_at": "2026-08-07T00:00:00Z",
  "authority": {{ "issuer_id": "org.security", "key_id": null }},
  "scope": {{ "tenant_ids": [], "environments": ["local"], "repository_ids": [] }},
  "rules": [{rules}]
}}"#
    )
}

const DENY_FORCE_PUSH: &str = r#"{
  "rule_id": "deny-force-push",
  "effect": "deny",
  "selectors": { "operation_kinds": ["git.force_update"] },
  "risk_categories": ["git.history_loss"],
  "rationale": "Force update destroys history.",
  "safer_alternatives": ["Use --force-with-lease"]
}"#;

fn parse(document: &str) -> Result<ofw_policy::ValidatedPolicyBundle, BundleError> {
    parse_bundle(document.as_bytes())
}

#[test]
fn a_valid_bundle_loads() {
    let bundle = match parse(&bundle_with(DENY_FORCE_PUSH)) {
        Ok(bundle) => bundle,
        Err(error) => unreachable!("the reference bundle must load: {error}"),
    };
    // It composes into an effective policy, which is what loading is for.
    match ofw_policy::EffectivePolicy::compose([bundle]) {
        Ok(_) => {}
        Err(error) => unreachable!("a loaded bundle must compose: {error:?}"),
    }
}

/// A supplied bundle cannot weaken, and the refusal is total.
///
/// `effect: "allow"` is not a value the deserializer accepts and then argues
/// about -- `Restriction` has no such variant, so the document does not match
/// the contract and no part of it loads.
#[test]
fn a_bundle_rule_cannot_declare_allow() {
    let allowing = DENY_FORCE_PUSH.replace(r#""effect": "deny""#, r#""effect": "allow""#);
    assert!(
        allowing.contains(r#""effect": "allow""#),
        "fixture must apply"
    );
    assert_eq!(
        parse(&bundle_with(&allowing)),
        Err(BundleError::MalformedShape)
    );
}

/// A supplied bundle cannot claim to be the built-in baseline.
#[test]
fn a_bundle_cannot_claim_the_builtin_layer() {
    let document =
        bundle_with(DENY_FORCE_PUSH).replace(r#""layer": "organization""#, r#""layer": "builtin""#);
    assert_eq!(parse(&document), Err(BundleError::MalformedShape));
}

/// Unknown fields are rejected rather than ignored.
///
/// An ignored unknown field is a rule that means something the reader cannot
/// see: a future selector this build does not understand would narrow the
/// rule, and dropping it silently broadens what the rule matches.
#[test]
fn unknown_fields_are_rejected_at_every_level() {
    let cases = [
        // Top level.
        bundle_with(DENY_FORCE_PUSH).replace(
            r#""schema_version": "1.0","#,
            r#""schema_version": "1.0", "extra": 1,"#,
        ),
        // Rule level.
        bundle_with(&DENY_FORCE_PUSH.replace(
            r#""effect": "deny","#,
            r#""effect": "deny", "unknown_rule_field": true,"#,
        )),
        // Selector level -- the one that would silently broaden a rule.
        bundle_with(&DENY_FORCE_PUSH.replace(
            r#""operation_kinds": ["git.force_update"]"#,
            r#""operation_kinds": ["git.force_update"], "future_selector": ["x"]"#,
        )),
    ];
    for document in cases {
        assert_eq!(parse(&document), Err(BundleError::MalformedShape));
    }
}

#[test]
fn contract_bounds_and_uniqueness_are_enforced() {
    // Duplicate in a uniqueItems array: absorbed silently by a set, rejected
    // here.
    let duplicated = DENY_FORCE_PUSH.replace(
        r#"["git.history_loss"]"#,
        r#"["git.history_loss", "git.history_loss"]"#,
    );
    assert_eq!(
        parse(&bundle_with(&duplicated)),
        Err(BundleError::DuplicateValue)
    );

    // A present but empty selector array. Accepting it would widen the rule.
    let emptied = DENY_FORCE_PUSH.replace(r#"["git.force_update"]"#, "[]");
    assert_eq!(
        parse(&bundle_with(&emptied)),
        Err(BundleError::EmptySelectorValues)
    );

    // Oversized input is refused before it is parsed.
    let oversized = vec![b'{'; MAX_BUNDLE_BYTES + 1];
    assert_eq!(parse_bundle(&oversized), Err(BundleError::TooLarge));

    // Unsupported schema version fails explicitly rather than best-effort.
    let future = bundle_with(DENY_FORCE_PUSH)
        .replace(r#""schema_version": "1.0""#, r#""schema_version": "2.0""#);
    assert_eq!(parse(&future), Err(BundleError::UnsupportedSchemaVersion));

    // Malformed JSON is distinguished from a well-formed non-bundle.
    assert_eq!(parse("{not json"), Err(BundleError::MalformedSyntax));
    assert_eq!(parse("[]"), Err(BundleError::MalformedShape));
}

#[test]
fn an_unbounded_or_malformed_timestamp_is_refused() {
    for replacement in [
        r#""issued_at": """#,
        r#""issued_at": "yesterday""#,
        r#""issued_at": "2026-08-07 00:00:00Z""#,
        r#""issued_at": "2026-08-07T00:00:00Z-padded-well-past-the-bound-and-then-some""#,
    ] {
        let document = bundle_with(DENY_FORCE_PUSH)
            .replace(r#""issued_at": "2026-08-07T00:00:00Z""#, replacement);
        assert!(
            matches!(
                parse(&document),
                Err(BundleError::InvalidIssuedAt | BundleError::MalformedShape)
            ),
            "must refuse {replacement}"
        );
    }
}

/// Diagnostics must not echo the policy file.
///
/// Negative/abuse test rather than a red-first witness: `BundleError` carries
/// no owned text by construction, so there is no guard to remove. It defends
/// the property against a future change that starts attaching the underlying
/// parser's message, which quotes the input.
#[test]
fn no_bundle_content_reaches_the_error() {
    const CANARY: &str = "CANARY_SECRET_a1b2c3d4e5";

    let leaky = bundle_with(&DENY_FORCE_PUSH.replace(
        "Force update destroys history.",
        &format!("Force update destroys history. {CANARY}"),
    ))
    .replace(r#""schema_version": "1.0""#, r#""schema_version": "9.9""#);

    match parse(&leaky) {
        Ok(_) => unreachable!("the fixture must fail to load"),
        Err(error) => {
            assert!(!format!("{error}").contains(CANARY), "Display leaked");
            assert!(!format!("{error:?}").contains(CANARY), "Debug leaked");
        }
    }
}

/// Retained red-first witness: a loader that skips rules it cannot parse.
///
/// This is the "be liberal in what you accept" failure applied to a policy
/// file. The thing quietly dropped is a restriction.
fn vulnerable_skips_unparsable_rules(documents: &[&str]) -> usize {
    documents
        .iter()
        .filter(|document| parse(&bundle_with(document)).is_ok())
        .count()
}

#[test]
fn red_first_witness_detects_skipped_rules() {
    // A second deny rule whose rationale is empty: a real rule, invalid by the
    // contract, carrying a real restriction.
    let broken = DENY_FORCE_PUSH
        .replace("deny-force-push", "deny-history-rewrite")
        .replace("Force update destroys history.", "");

    let both = format!("{DENY_FORCE_PUSH},{broken}");
    // The real loader refuses the document: one bad rule is a bad bundle.
    assert_eq!(
        parse(&bundle_with(&both)),
        Err(BundleError::Invalid(
            ofw_policy::PolicyError::InvalidRationale
        ))
    );

    // The retained witness keeps the rules that happened to parse, and the
    // restriction the broken rule carried is simply gone.
    assert_eq!(
        vulnerable_skips_unparsable_rules(&[DENY_FORCE_PUSH, &broken]),
        1
    );
}
