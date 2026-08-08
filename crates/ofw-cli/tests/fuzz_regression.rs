//! Deterministic replay of the fuzz corpus, on the pinned stable toolchain.
//!
//! Coverage-guided fuzzing needs nightly and runs separately. This does not:
//! it replays every seed in `tests/fuzz-corpus/` through the parser it belongs
//! to, on the same toolchain everything else is built with.
//!
//! The division of labour is the point. Fuzzing *finds* inputs; this *keeps*
//! them. A crash discovered once and added to the corpus stays checked on
//! every ordinary `cargo test` run forever, without anyone needing nightly
//! installed to know whether it regressed. A repository where the regression
//! test only runs under the fuzzing toolchain is a repository where the
//! regression test effectively does not run.
//!
//! The assertion is termination without panic. Each parser is total by design
//! -- every input maps to a typed success or a typed refusal -- so a panic is
//! the failure, and in the hook's case a panic is an abnormal exit, which the
//! host reads as a hook failure, and a hook failure lets the tool call
//! proceed.

use std::path::{Path, PathBuf};

/// The operation kinds this build interprets, pinned per grammar revision.
///
/// Written out rather than read from `ofw-intent`'s own table, because a pin
/// that reads the thing it pins agrees with it always. An unrecognised
/// revision yields an empty set, so a bump fails every supported seed until
/// this list is updated — which is the intended way to be told.
///
/// This list existed before and went stale anyway: `git log` and `git diff`
/// were added to the grammar while both copies of it still named only
/// `status` and `rev-parse`. Nothing here caught it, because the corpus had no
/// seed that classified as either new kind, and the nightly fuzz job found it
/// instead — on a `git diff` the fuzzer generated in eight bytes. The corpus
/// now carries those shapes, so the same drift reds on an ordinary
/// `cargo test`.
fn interpreted_kinds() -> &'static [&'static str] {
    match ofw_intent::GRAMMAR_REVISION {
        // 1.2.0 added the apply-patch subset, which has its own entry
        // point and its own target; the shell subset it widened by
        // nothing, and this arm restates that rather than sharing one.
        "1.2.0" => &["git.status", "git.rev_parse", "git.log", "git.diff"],
        _ => &[],
    }
}

fn corpus(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fuzz-corpus")
        .join(target);

    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) => unreachable!("corpus {} must be readable: {error}", directory.display()),
    };

    let mut seeds = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => unreachable!("corpus entry must be readable: {error}"),
        };
        let path = entry.path();
        if path.is_file() {
            match std::fs::read(&path) {
                Ok(bytes) => seeds.push((path, bytes)),
                Err(error) => unreachable!("seed must be readable: {error}"),
            }
        }
    }
    seeds.sort_by(|left, right| left.0.cmp(&right.0));

    // An empty corpus would make every test below pass without checking
    // anything, which is the failure mode this whole file exists to avoid
    // elsewhere.
    assert!(
        !seeds.is_empty(),
        "corpus {} is empty; the replay would assert nothing",
        directory.display()
    );
    seeds
}

#[test]
fn every_envelope_seed_terminates_without_panicking() {
    for (path, bytes) in corpus("envelope") {
        let assessment = ofw_adapter_codex::assess_supported_pre_tool_use(&bytes);
        // Total by construction: every input is one of the two arms. Matching
        // exhaustively means a future third arm has to be considered here.
        match assessment {
            ofw_adapter_codex::AdapterAssessment::Extracted(_)
            | ofw_adapter_codex::AdapterAssessment::Indeterminate(_) => {}
        }
        let _ = path;
    }
}

#[test]
fn every_bundle_seed_terminates_without_panicking() {
    for (path, bytes) in corpus("bundle") {
        // Whatever parses must also compose; a bundle that loads and then
        // cannot be used would strand an operator with a policy that is
        // neither active nor reported as broken.
        if let Ok(bundle) = ofw_policy::parse_bundle(&bytes)
            && ofw_policy::EffectivePolicy::compose([bundle]).is_err()
        {
            unreachable!("{} parsed but did not compose", path.display());
        }
    }
}

#[test]
fn every_command_seed_terminates_and_classifies_within_the_subset() {
    for (path, bytes) in corpus("command") {
        let Ok(command) = core::str::from_utf8(&bytes) else {
            continue;
        };
        match ofw_intent::interpret(command) {
            Ok(ofw_intent::Classification::Supported(candidate)) => {
                // Anything classified as supported must be a kind this build
                // actually interprets. A candidate carrying an unexpected kind
                // means the classifier recognised something it has no rules
                // for, which is how a dangerous command gets reported as a
                // harmless one.
                let kind = candidate.operation_kind().as_str();
                assert!(
                    interpreted_kinds().contains(&kind),
                    "{} classified as unexpected kind {kind}",
                    path.display()
                );
                assert_eq!(
                    candidate.effect(),
                    ofw_contracts::OperationEffect::Read,
                    "{} is not a read",
                    path.display()
                );
            }
            Ok(ofw_intent::Classification::Unsupported(_)) | Err(_) => {}
        }
    }
}

/// The patch kinds this build interprets, pinned per grammar revision.
///
/// Separate from [`interpreted_kinds`] because the two grammars have separate
/// entry points and separate revisions of meaning. Sharing one list would let a
/// shell kind satisfy a patch assertion.
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

#[test]
fn every_patch_seed_terminates_and_classifies_within_the_subset() {
    for (path, bytes) in corpus("patch") {
        let Ok(document) = core::str::from_utf8(&bytes) else {
            continue;
        };
        match ofw_intent::interpret_patch(document) {
            ofw_intent::PatchClassification::Supported(candidate) => {
                let kind = candidate.operation_kind().as_str();
                assert!(
                    patch_kinds().contains(&kind),
                    "{} classified as unexpected kind {kind}",
                    path.display()
                );
                // The properties the resolver is entitled to assume, replayed
                // on stable rather than only under nightly libFuzzer. It
                // appends missing path components without canonicalizing them,
                // so an absolute path or a surviving traversal here would reach
                // the containment check as text.
                assert!(
                    !candidate.path_candidates().is_empty(),
                    "{} named no path",
                    path.display()
                );
                for candidate_path in candidate.path_candidates() {
                    assert!(
                        !candidate_path.starts_with('/') && !candidate_path.starts_with('\\'),
                        "{} yielded an absolute path {candidate_path}",
                        path.display()
                    );
                    for component in candidate_path.split(['/', '\\']) {
                        assert!(
                            component != "." && component != "..",
                            "{} yielded a traversal component in {candidate_path}",
                            path.display()
                        );
                    }
                }
            }
            ofw_intent::PatchClassification::Unsupported(_) => {}
        }
    }
}

/// The seed that matters most, asserted by name rather than only in bulk.
///
/// A tokenizer that skipped the operator would report a harmless `git status`
/// for this. The bulk replay above would still pass -- `git.status` is a
/// permitted kind -- so the specific input needs its own assertion.
#[test]
fn the_operator_injection_seed_is_refused_rather_than_reduced() {
    let seeds = corpus("command");
    let injection = seeds
        .iter()
        .find(|(path, _)| path.ends_with("operator-injection"));
    let (_, bytes) = match injection {
        Some(seed) => seed,
        None => unreachable!("the operator-injection seed must be in the corpus"),
    };
    let command = match core::str::from_utf8(bytes) {
        Ok(command) => command,
        Err(error) => unreachable!("the seed must be UTF-8: {error}"),
    };

    assert!(
        ofw_intent::interpret(command).is_err(),
        "a command carrying a shell operator must be refused, not reduced"
    );
}
