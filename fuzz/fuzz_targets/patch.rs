#![no_main]

//! Fuzzes the apply-patch grammar.
//!
//! The fourth untrusted parser, and the first that describes a *write*. Its
//! input arrives from an agent through the Codex envelope, so every byte is
//! attacker-influenced, and unlike the other three a misclassification here
//! does not merely mislabel a read.
//!
//! What is asserted is not "does not crash" -- libFuzzer gives that for free --
//! but that anything classified as supported is one of the kinds this build
//! actually interprets, and that its paths satisfy the properties the resolver
//! is entitled to assume. The resolver appends path components nobody
//! canonicalizes, so a traversal reaching it would walk back out of the
//! boundary as text. That assumption is checked here against arbitrary input
//! rather than only against the fixtures someone thought to write.

use libfuzzer_sys::fuzz_target;

/// The operation kinds this build interprets, pinned per grammar revision.
///
/// Written out rather than read from `ofw-intent`'s own table, because a pin
/// that reads the thing it pins agrees with it always. An unrecognised revision
/// yields an empty set, so a bump fails every supported input until this list
/// is updated -- which is the intended way to be told.
fn patch_kinds() -> &'static [&'static str] {
    match ofw_intent::GRAMMAR_REVISION {
        "1.2.0" => &[
            "patch.add_file",
            "patch.update_file",
            "patch.delete_file",
            "patch.move_file",
        ],
        _ => &[],
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(document) = core::str::from_utf8(data) else {
        return;
    };
    let ofw_intent::PatchClassification::Supported(candidate) =
        ofw_intent::interpret_patch(document)
    else {
        return;
    };

    let kind = candidate.operation_kind().as_str().to_owned();
    assert!(
        patch_kinds().contains(&kind.as_str()),
        "unexpected supported patch kind: {kind} (grammar revision {})",
        ofw_intent::GRAMMAR_REVISION
    );

    // A supported document names at least one path. The resolver treats a
    // patch kind arriving with none as a contradiction between the layers, and
    // this is the layer that must not produce it.
    assert!(
        !candidate.path_candidates().is_empty(),
        "a supported patch named no path"
    );

    for path in candidate.path_candidates() {
        // The resolver appends missing components without canonicalizing them,
        // so these three properties are what stand between an accepted document
        // and a write outside the repository boundary.
        assert!(!path.is_empty(), "an empty path candidate");
        assert!(
            !path.starts_with('/') && !path.starts_with('\\'),
            "an absolute path candidate: {path}"
        );
        for component in path.split(['/', '\\']) {
            assert!(
                component != "." && component != "..",
                "a traversal component survived: {path}"
            );
        }
    }
});
