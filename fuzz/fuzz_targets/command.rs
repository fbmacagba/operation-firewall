#![no_main]

//! The shell tokenizer is the component whose failure is most dangerous: one
//! that mis-parses reports a harmless operation for a dangerous string.

use libfuzzer_sys::fuzz_target;

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
            kind == "git.status" || kind == "git.rev_parse",
            "unexpected supported operation kind: {kind}"
        );
        // The subset is read-only, and every git invocation carries an
        // execution surface. Neither may drift without this failing.
        assert_eq!(candidate.effect(), ofw_contracts::OperationEffect::Read);
    }
});
