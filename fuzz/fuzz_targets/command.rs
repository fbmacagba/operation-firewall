#![no_main]

//! The shell tokenizer is the component whose failure is most dangerous: one
//! that mis-parses reports a harmless operation for a dangerous string.

use libfuzzer_sys::fuzz_target;

/// The operation kinds this build interprets, pinned per grammar revision.
///
/// Written out rather than read from `ofw-intent`'s own table, because a pin
/// that reads the thing it pins agrees with it always. An unrecognised
/// revision yields an empty set, so a bump fails every supported input until
/// this list is updated.
///
/// The revision match is what this file was missing. It previously named
/// `git.status` and `git.rev_parse` as bare literals, and when `git log` and
/// `git diff` joined the grammar this target started failing on the string
/// `git diff` — which the fuzzer found in eight bytes. `fuzz/` is excluded
/// from the workspace so the ordinary gate never compiles or runs this file,
/// and the drift was invisible until the nightly job. Keyed on the revision,
/// the same widening now fails loudly and says why rather than looking like a
/// crash in the parser.
fn interpreted_kinds() -> &'static [&'static str] {
    match ofw_intent::GRAMMAR_REVISION {
        // 1.2.0 added the apply-patch subset, which has its own entry
        // point and its own target; the shell subset it widened by
        // nothing, and this arm restates that rather than sharing one.
        "1.2.0" => &["git.status", "git.rev_parse", "git.log", "git.diff"],
        _ => &[],
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(command) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(ofw_intent::Classification::Supported(candidate)) = ofw_intent::interpret(command) {
        // Anything classified as supported must be one of the kinds this
        // build actually interprets. A candidate carrying an unexpected kind
        // would mean the classifier recognised something it has no rules for.
        let kind = candidate.operation_kind().as_str().to_owned();
        assert!(
            interpreted_kinds().contains(&kind.as_str()),
            "unexpected supported operation kind: {kind} \
             (grammar revision {})",
            ofw_intent::GRAMMAR_REVISION
        );
        // The subset is read-only, and every git invocation carries an
        // execution surface. Neither may drift without this failing.
        assert_eq!(candidate.effect(), ofw_contracts::OperationEffect::Read);
        // Path operands exist only for kinds whose grammar declares them, and
        // only after an explicit separator. A candidate carrying operands for
        // a kind that takes none means the two layers disagree about what the
        // command is, which the resolver refuses -- but it should never be
        // constructible in the first place.
        if !candidate.path_candidates().is_empty() {
            assert!(
                kind == "git.log" || kind == "git.diff",
                "{kind} carries path operands but its grammar accepts none"
            );
        }
    }
});
