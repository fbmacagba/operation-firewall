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

/// Replaces the reference bundle's timestamp, keeping everything else valid.
fn bundle_issued_at(issued_at: &str) -> String {
    bundle_with(DENY_FORCE_PUSH).replace(
        r#""issued_at": "2026-08-07T00:00:00Z""#,
        &format!(r#""issued_at": "{issued_at}""#),
    )
}

/// Every structural check on the timestamp is load-bearing on its own.
///
/// Five of the six branches of `validate_issued_at` survived a mutation run.
/// The existing coverage above refuses malformed timestamps, but every case it
/// uses is wrong in more than one way at once, so no single check had to work:
/// `"yesterday"` fails the digit scan at its very first index and never reaches
/// the separator checks below it.
///
/// The cases here are wrong in exactly one way each, which is what it takes to
/// hold an individual condition. Each separator is checked in isolation because
/// the real `||` chain is satisfied by any one of them failing -- turning one
/// into `&&` leaves a document that is refused only when two separators are
/// wrong together, and nothing here was noticing that.
#[test]
fn each_timestamp_check_refuses_on_its_own() {
    // Shorter than the shortest accepted form. Under a mutation of the floor
    // this does not merely load -- it reaches `bytes[11]` on a ten-byte string
    // and panics, and a panic in this binary is exit 101, which the Codex host
    // treats as fail-open. See docs/milestone-1/mutation-triage.md.
    for truncated in ["2026-08-07", "2026-08-07T00:00:0"] {
        assert_eq!(
            parse(&bundle_issued_at(truncated)),
            Err(BundleError::InvalidIssuedAt),
            "a timestamp of {} bytes is below the shortest accepted form",
            truncated.len()
        );
    }

    // One separator wrong at a time, everything else valid.
    for broken in [
        "2026x08-07T00:00:00Z",
        "2026-08x07T00:00:00Z",
        "2026-08-07x00:00:00Z",
        "2026-08-07T00x00:00Z",
        "2026-08-07T00:00x00Z",
    ] {
        assert_eq!(
            parse(&bundle_issued_at(broken)),
            Err(BundleError::InvalidIssuedAt),
            "one wrong separator is enough: {broken}"
        );
    }

    // A byte that is neither graphic nor a space, in a string that is
    // otherwise exactly the right shape. Non-ASCII rather than a control
    // character because a raw control byte is not legal inside a JSON string
    // and would be refused as malformed syntax before reaching the check
    // under test -- the wrong layer, and the fixture would prove nothing.
    assert_eq!(
        parse(&bundle_issued_at("2026-08-07T00:00:00é")),
        Err(BundleError::InvalidIssuedAt),
        "a byte that is neither graphic nor a space is refused"
    );

    // The length bound, pinned from below as well as above. 35 bytes is the
    // longest accepted form and it is a real timestamp, not padding.
    const LONGEST_TIMESTAMP: usize = 35;
    let longest = "2026-08-07T00:00:00.123456789+00:00";
    assert_eq!(longest.len(), LONGEST_TIMESTAMP, "the fixture is exact");
    assert!(
        parse(&bundle_issued_at(longest)).is_ok(),
        "a timestamp of exactly the limit is accepted"
    );
    for excess in [1, 2, LONGEST_TIMESTAMP] {
        let over = format!("{longest}{}", "0".repeat(excess));
        assert_eq!(
            parse(&bundle_issued_at(&over)),
            Err(BundleError::InvalidIssuedAt),
            "a timestamp {excess} bytes over the limit must be refused"
        );
    }
}

/// The document and array bounds are enforced at their boundaries.
///
/// Same shape as every other bound in this workspace: a single over-limit case
/// is satisfied by a mutation that refuses *only* that value and lets
/// everything larger through, so each bound is pinned from below and from far
/// above.
///
/// The over-limit cases assert `TooManyValues` specifically rather than "some
/// error". The policy types re-check these bounds themselves, so a bundle that
/// gets past the loader's check is still refused -- by a later guard, reported
/// as a different error. Accepting any error here would let the loader's own
/// bound rot while the test kept passing.
#[test]
fn the_bundle_and_array_bounds_hold_at_their_boundaries() {
    // The reference document plus trailing whitespace, which JSON ignores.
    let padded_to = |total: usize| {
        let document = bundle_with(DENY_FORCE_PUSH);
        let padding = " ".repeat(total - document.len());
        format!("{document}{padding}")
    };
    let at_limit = padded_to(MAX_BUNDLE_BYTES);
    assert_eq!(at_limit.len(), MAX_BUNDLE_BYTES, "the fixture is exact");
    assert!(
        parse(&at_limit).is_ok(),
        "a bundle of exactly the limit is accepted"
    );
    for excess in [1, 2, 4_096] {
        assert_eq!(
            parse(&padded_to(MAX_BUNDLE_BYTES + excess)),
            Err(BundleError::TooLarge),
            "a bundle {excess} bytes over the limit must be refused"
        );
    }

    // `unique_set`'s bound, reached through `risk_categories`.
    const MAX_NAME_SET: usize = 64;
    let with_risk_categories = |count: usize| {
        let categories: Vec<String> = (0..count)
            .map(|index| format!(r#""git.risk{index}""#))
            .collect();
        DENY_FORCE_PUSH.replace(
            r#"["git.history_loss"]"#,
            &format!("[{}]", categories.join(",")),
        )
    };
    assert!(
        parse(&bundle_with(&with_risk_categories(MAX_NAME_SET))).is_ok(),
        "exactly the limit is accepted"
    );
    for excess in [1, 2, MAX_NAME_SET] {
        assert_eq!(
            parse(&bundle_with(&with_risk_categories(MAX_NAME_SET + excess))),
            Err(BundleError::TooManyValues),
            "{excess} risk categories over the limit must be refused"
        );
    }

    // The safer-alternatives bound, which the loader checks directly.
    const MAX_SAFER_ALTERNATIVES: usize = 8;
    let with_alternatives = |count: usize| {
        let alternatives: Vec<String> = (0..count)
            .map(|index| format!(r#""Alternative {index}""#))
            .collect();
        DENY_FORCE_PUSH.replace(
            r#"["Use --force-with-lease"]"#,
            &format!("[{}]", alternatives.join(",")),
        )
    };
    assert!(
        parse(&bundle_with(&with_alternatives(MAX_SAFER_ALTERNATIVES))).is_ok(),
        "exactly the limit is accepted"
    );
    for excess in [1, 2, MAX_SAFER_ALTERNATIVES] {
        assert_eq!(
            parse(&bundle_with(&with_alternatives(
                MAX_SAFER_ALTERNATIVES + excess
            ))),
            Err(BundleError::TooManyValues),
            "{excess} safer alternatives over the limit must be refused"
        );
    }
}

/// Every reason a bundle failed to load renders as distinct, non-empty text.
///
/// A refusal to load is never a weaker policy, so the operator's only question
/// is *why* -- and "not valid JSON" and "does not match the v1 contract" are
/// different repairs. An empty or shared message makes them the same message.
#[test]
fn every_bundle_error_renders_a_distinct_message() {
    let all = [
        BundleError::TooLarge,
        BundleError::NotUtf8,
        BundleError::MalformedSyntax,
        BundleError::MalformedShape,
        BundleError::UnsupportedSchemaVersion,
        BundleError::InvalidIssuedAt,
        BundleError::EmptySelectorValues,
        BundleError::DuplicateValue,
        BundleError::TooManyValues,
        BundleError::Invalid(ofw_policy::PolicyError::InvalidRationale),
    ];

    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for error in all.clone() {
        let rendered = match error {
            // Exhaustive on purpose. A variant added later stops compiling here
            // until it is named, so this test cannot silently fall behind the
            // enum it claims to cover.
            BundleError::TooLarge
            | BundleError::NotUtf8
            | BundleError::MalformedSyntax
            | BundleError::MalformedShape
            | BundleError::UnsupportedSchemaVersion
            | BundleError::InvalidIssuedAt
            | BundleError::EmptySelectorValues
            | BundleError::DuplicateValue
            | BundleError::TooManyValues
            | BundleError::Invalid(_) => error.to_string(),
        };
        assert!(!rendered.is_empty(), "{error:?} renders nothing");
        assert!(seen.insert(rendered), "{error:?} shares another message");
    }
    assert_eq!(seen.len(), all.len());
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
