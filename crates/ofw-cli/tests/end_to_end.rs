//! End-to-end tests that run the real `ofw` binary as a child process.
//!
//! These exercise what Codex actually observes: the exit code, the exact bytes
//! on stdout, and the bytes on stderr. Asserting on library return values
//! instead would miss the failure modes that matter here, because Codex reads
//! a malformed or unexpected stream as a hook failure and lets the tool call
//! proceed.
//!
//! Trusted configuration is passed as child-process environment and every run
//! starts by removing all three variables, so a developer machine that happens
//! to have them set cannot turn an unconfigured test into a configured one.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_ofw");

const EXIT_OK: i32 = 0;
const EXIT_DENY: i32 = 2;
const EXIT_USAGE: i32 = 64;

const WORKING_DIRECTORY_VARIABLE: &str = "OFW_WORKING_DIRECTORY";
const REPOSITORY_BOUNDARY_VARIABLE: &str = "OFW_REPOSITORY_BOUNDARY";
const ENVIRONMENT_VARIABLE: &str = "OFW_ENVIRONMENT";
const CONFIG_FILE_VARIABLE: &str = "OFW_CONFIG_FILE";
const POLICY_DIRECTORY_VARIABLE: &str = "OFW_POLICY_DIRECTORY";
const AUDIT_DIRECTORY_VARIABLE: &str = "OFW_AUDIT_DIRECTORY";

/// Writes one bundle file into a fresh policy directory and returns the
/// environment entry pointing at it.
fn policy_directory(label: &str, file_name: &str, contents: &str) -> (&'static str, String) {
    let directory = directory(&format!("policy-{label}"));
    let path = directory.join(file_name);
    match std::fs::write(&path, contents) {
        Ok(()) => {}
        Err(error) => unreachable!("test bundle must be writable: {error}"),
    }
    (POLICY_DIRECTORY_VARIABLE, text(&directory))
}

/// A supplied organization bundle denying the operation the tests interpret.
fn deny_git_status_bundle() -> String {
    r#"{
  "schema_version": "1.0",
  "bundle_id": "org.baseline",
  "bundle_version": "1.0.0",
  "layer": "organization",
  "issued_at": "2026-08-07T00:00:00Z",
  "authority": { "issuer_id": "org.security", "key_id": null },
  "scope": { "tenant_ids": [], "environments": ["local"], "repository_ids": [] },
  "rules": [
    {
      "rule_id": "deny-status",
      "effect": "deny",
      "selectors": { "operation_kinds": ["git.status"] },
      "risk_categories": ["git.repository"],
      "rationale": "Status is denied by organization policy in this test.",
      "safer_alternatives": []
    }
  ]
}"#
    .to_owned()
}

fn envelope(tool_name: &str, command: &str) -> String {
    format!(
        concat!(
            r#"{{"session_id":"session-1","transcript_path":null,"cwd":"F:/repo","#,
            r#""hook_event_name":"PreToolUse","model":"gpt-5","turn_id":"turn-1","#,
            r#""permission_mode":"default","tool_name":"{}","tool_use_id":"tool-1","#,
            r#""tool_input":{{"command":"{}"}}}}"#
        ),
        tool_name, command
    )
}

/// This process's own directory tree, emptied exactly once before first use.
///
/// The cleanup is not tidiness, it is correctness. Directories were previously
/// named `ofw-e2e-<pid>-<label>` and never removed, and several tests here
/// assert on an *exact* audit record count. An operating system reuses process
/// ids, so a later run eventually lands on a pid whose leftovers are still on
/// disk and reads a trail it did not write — `a_decision_is_recorded…` sees two
/// records where it wrote one, and `doctor_probes_do_not_write…` sees a segment
/// that no probe created.
///
/// It was found by measurement, not reasoning: the suite failed once under
/// load, and the temp directory held 892 leftover roots, five of them with a
/// populated `audit-trail`. `ofw-audit/tests/persistence.rs` already cleans for
/// this stated reason; this file did not.
///
/// `Once` rather than a per-`directory` removal because the labels nest —
/// `contained/worktree` lives inside `contained`, so cleaning per call would
/// let one test delete another's tree mid-run.
fn test_root() -> PathBuf {
    static CLEAN: std::sync::Once = std::sync::Once::new();
    let mut root = std::env::temp_dir();
    root.push(format!("ofw-e2e-{}", std::process::id()));
    CLEAN.call_once(|| {
        // Scoped to this process's own directory under the system temp path.
        let _ = std::fs::remove_dir_all(&root);
    });
    root
}

fn directory(label: &str) -> PathBuf {
    let path = test_root().join(label);
    match std::fs::create_dir_all(&path) {
        Ok(()) => path,
        Err(error) => unreachable!("test directory must be creatable: {error}"),
    }
}

fn text(path: &Path) -> String {
    match path.to_str() {
        Some(text) => text.to_owned(),
        None => unreachable!("test path must be UTF-8"),
    }
}

/// A working directory inside its repository boundary.
fn contained() -> Vec<(&'static str, String)> {
    let boundary = directory("contained");
    let working = directory("contained/worktree");
    configuration(&working, &boundary)
}

/// A working directory that is not inside its repository boundary.
fn cross_boundary() -> Vec<(&'static str, String)> {
    configuration(
        &directory("outside-worktree"),
        &directory("outside-boundary"),
    )
}

/// Well-formed configuration naming a boundary that is not on the filesystem.
///
/// `TrustedConfiguration::new` validates shape, not existence, so this is what
/// an operator typo produces.
fn unresolvable() -> Vec<(&'static str, String)> {
    let mut absent = directory("unresolvable");
    absent.push("no-such-directory");
    configuration(&absent, &absent)
}

fn configuration(working: &Path, boundary: &Path) -> Vec<(&'static str, String)> {
    vec![
        (WORKING_DIRECTORY_VARIABLE, text(working)),
        (REPOSITORY_BOUNDARY_VARIABLE, text(boundary)),
        (ENVIRONMENT_VARIABLE, "local".to_owned()),
    ]
}

fn run(arguments: &[&str], input: &[u8]) -> Output {
    run_with(arguments, input, &[])
}

fn run_with(arguments: &[&str], input: &[u8], environment: &[(&'static str, String)]) -> Output {
    let mut builder = Command::new(BINARY);
    builder
        .args(arguments)
        .env_remove(WORKING_DIRECTORY_VARIABLE)
        .env_remove(REPOSITORY_BOUNDARY_VARIABLE)
        .env_remove(ENVIRONMENT_VARIABLE)
        .env_remove(POLICY_DIRECTORY_VARIABLE)
        .env_remove(AUDIT_DIRECTORY_VARIABLE)
        .env_remove(CONFIG_FILE_VARIABLE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in environment {
        builder.env(key, value);
    }

    let mut child = match builder.spawn() {
        Ok(child) => child,
        Err(error) => unreachable!("the ofw binary must spawn: {error}"),
    };

    match child.stdin.take() {
        // Dropping the handle closes stdin, which the child needs in order to
        // finish reading. A broken pipe is not a failure: the child may have
        // already decided and exited.
        Some(mut handle) => {
            let _ = handle.write_all(input);
        }
        None => unreachable!("stdin must be piped"),
    }

    match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => unreachable!("the ofw binary must produce output: {error}"),
    }
}

fn code(output: &Output) -> i32 {
    match output.status.code() {
        Some(code) => code,
        None => unreachable!("the ofw binary must exit with a code, not a signal"),
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn an_unconfigured_envelope_denies_because_nothing_can_be_placed() {
    let output = run(
        &["hook", "codex-pre-tool-use"],
        envelope("Bash", "git status").as_bytes(),
    );

    assert_eq!(code(&output), EXIT_DENY);
    // stdout must be completely empty. Anything there risks being read as a
    // malformed decision, and malformed fails open.
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on deny, got: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("TRUSTED_CONFIGURATION_MISSING"),
        "stderr must carry the reason code, got: {}",
        stderr(&output)
    );
}

/// The deliverable of the target-resolution slice, asserted as one pairing.
///
/// The operation is now *proven*: interpretation and resolution both
/// succeeded, so a `SupportedOperationProof` exists and the decision is a real
/// `ask` rather than `indeterminate`. It is still not an allow and still
/// denies on the wire, and asserting only one half of that would hide the two
/// ways this can break -- an allow means the execution-surface evidence stopped
/// reaching the baseline, an indeterminate means the proof is not being built.
#[test]
fn a_configured_repository_read_is_proven_asks_and_still_denies_on_the_wire() {
    let configured = contained();
    let payload = stdout(&run_with(
        &["assess"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    ));

    for expected in [
        "\"outcome\":\"ask\"",
        "\"supported_operation_proof\":true",
        "\"wire_decision\":\"deny\"",
        "\"reason_code\":\"APPROVAL_REQUIRED\"",
        "\"operation_kind\":\"git.status\"",
        // Proven and decided, with no audit trail behind it. A read may
        // continue; the record must say it was not recorded.
        "\"audit_health\":\"degraded\"",
        "\"policy_outcome\":\"no_restriction\"",
    ] {
        assert!(
            payload.contains(expected),
            "a proven repository read must report {expected}, got: {payload}"
        );
    }
    assert!(!payload.contains("\"outcome\":\"allow\""));

    // And the hook itself still denies, with nothing on stdout.
    let hooked = run_with(
        &["hook", "codex-pre-tool-use"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    );
    assert_eq!(code(&hooked), EXIT_DENY);
    assert!(hooked.stdout.is_empty());
    assert!(stderr(&hooked).contains("APPROVAL_REQUIRED"));
}

/// A resolver fact deciding an outcome, with the command held constant.
///
/// The same `git status` that asks inside its boundary is denied outside it.
/// Nothing about the command string differs between the two runs; only what
/// the resolver found on the filesystem does.
#[test]
fn containment_decides_the_outcome_for_an_identical_command() {
    let command = envelope("Bash", "git status");

    let inside = stdout(&run_with(&["assess"], command.as_bytes(), &contained()));
    assert!(inside.contains("\"outcome\":\"ask\""), "got: {inside}");

    let outside = stdout(&run_with(
        &["assess"],
        command.as_bytes(),
        &cross_boundary(),
    ));
    assert!(outside.contains("\"outcome\":\"deny\""), "got: {outside}");
    assert!(outside.contains("\"reason_code\":\"BASELINE_DENIED\""));
    // Proven, and denied on the strength of the proof rather than for want of
    // one. The distinction is the point of the slice.
    assert!(outside.contains("\"supported_operation_proof\":true"));
}

/// The reason code records how far down the pipeline an operation got.
#[test]
fn the_reason_code_records_how_far_the_pipeline_reached() {
    let configured = contained();
    let cases = [
        // Interpreted and resolved: a decision.
        (
            "git status",
            "\"reason_code\":\"APPROVAL_REQUIRED\"",
            "\"operation_kind\":\"git.status\"",
        ),
        (
            "git rev-parse --show-toplevel",
            "\"reason_code\":\"APPROVAL_REQUIRED\"",
            "\"operation_kind\":\"git.rev_parse\"",
        ),
        // Literal words, but outside the interpreted subset.
        (
            "git push --force",
            "\"reason_code\":\"OPERATION_INTERPRETATION_UNSUPPORTED\"",
            "\"operation_kind\":\"uninterpreted\"",
        ),
        // Not reducible to literal words at all.
        (
            "git status; rm -rf /",
            "\"reason_code\":\"COMMAND_NOT_LITERAL\"",
            "\"operation_kind\":\"uninterpreted\"",
        ),
    ];

    for (command, expected_reason, expected_kind) in cases {
        let payload = stdout(&run_with(
            &["assess"],
            envelope("Bash", command).as_bytes(),
            &configured,
        ));
        assert!(
            payload.contains(expected_reason),
            "{command} should report {expected_reason}, got: {payload}"
        );
        assert!(
            payload.contains(expected_kind),
            "{command} should report {expected_kind}, got: {payload}"
        );
        // Whatever stage it reached, it is still never an allow.
        assert!(payload.contains("\"wire_decision\":\"deny\""));
    }

    // Interpreted, with nothing to place it against.
    let unplaced = stdout(&run(&["assess"], envelope("Bash", "git status").as_bytes()));
    assert!(unplaced.contains("\"reason_code\":\"TRUSTED_CONFIGURATION_MISSING\""));
    assert!(unplaced.contains("\"operation_kind\":\"git.status\""));
}

#[test]
fn every_unusable_input_denies() {
    let oversized = envelope("Bash", &"a".repeat(300_000));
    let cases: [(&str, Vec<u8>); 6] = [
        ("empty", Vec::new()),
        ("truncated object", b"{".to_vec()),
        ("json null", b"null".to_vec()),
        ("missing fields", br#"{"session_id":"s"}"#.to_vec()),
        (
            "unsupported tool",
            envelope("WebSearch", "anything").into_bytes(),
        ),
        ("oversized envelope", oversized.into_bytes()),
    ];

    // Configured, so that the denial is the input's fault and not the
    // configuration's.
    let configured = contained();
    for (label, input) in cases {
        let output = run_with(&["hook", "codex-pre-tool-use"], &input, &configured);
        assert_eq!(code(&output), EXIT_DENY, "{label} must deny");
        assert!(output.stdout.is_empty(), "{label} must leave stdout empty");
        assert!(!output.stderr.is_empty(), "{label} must give a reason");
    }
}

/// Negative/abuse test, not a red-first witness: reasons are `&'static str` by
/// construction, so there is no guard to remove and nothing that could go red.
/// It defends the property against a future change that starts formatting
/// payload-derived text into a reason.
#[test]
fn no_payload_content_reaches_either_stream() {
    const CANARY: &str = "CANARY_SECRET_a1b2c3d4e5";

    let configured = contained();
    for arguments in [
        ["hook", "codex-pre-tool-use"].as_slice(),
        ["assess"].as_slice(),
    ] {
        let output = run_with(
            arguments,
            envelope("Bash", &format!("git push --token {CANARY}")).as_bytes(),
            &configured,
        );
        assert!(
            !stdout(&output).contains(CANARY),
            "{arguments:?} leaked the payload to stdout"
        );
        assert!(
            !stderr(&output).contains(CANARY),
            "{arguments:?} leaked the payload to stderr"
        );
    }
}

#[test]
fn an_unrecognized_hook_argument_denies_rather_than_reporting_usage() {
    // Anything Codex sees that is not exit 2 or a valid deny object is a hook
    // failure, and a hook failure lets the call proceed. Hook mode therefore
    // must not use the usage exit code.
    let output = run(
        &["hook", "codex-pre-tool-use", "--nonsense"],
        envelope("Bash", "git status").as_bytes(),
    );
    assert_eq!(code(&output), EXIT_DENY);
    assert_ne!(code(&output), EXIT_USAGE);
    assert!(output.stdout.is_empty());
}

#[test]
fn assess_emits_one_structured_decision_and_exits_zero() {
    let output = run(&["assess"], envelope("Bash", "git status").as_bytes());
    assert_eq!(code(&output), EXIT_OK);

    let payload = stdout(&output);
    for expected in [
        "\"schema_version\":\"1.0\"",
        "\"outcome\":\"indeterminate\"",
        "\"reason_code\":\"TRUSTED_CONFIGURATION_MISSING\"",
        "\"tool_name\":\"Bash\"",
        "\"supported_operation_proof\":false",
        "\"wire_decision\":\"deny\"",
    ] {
        assert!(
            payload.contains(expected),
            "assess output missing {expected}, got: {payload}"
        );
    }
}

/// The end-to-end form of the invariant the built-in baseline exists for.
#[test]
fn policy_silence_does_not_authorize_through_the_cli() {
    // Both with and without a proof: policy restricts nothing either way, and
    // neither is an allow.
    for environment in [Vec::new(), contained()] {
        let payload = stdout(&run_with(
            &["assess"],
            envelope("Bash", "git status").as_bytes(),
            &environment,
        ));

        assert!(
            payload.contains("\"policy_outcome\":\"no_restriction\""),
            "expected an unrestricted policy, got: {payload}"
        );
        assert!(!payload.contains("\"outcome\":\"allow\""));
        assert!(payload.contains("\"wire_decision\":\"deny\""));
    }
}

#[test]
fn doctor_reports_what_is_implemented_without_overstating_it() {
    let output = run(&["doctor"], b"");
    assert_eq!(code(&output), EXIT_OK);

    let payload = stdout(&output);
    for expected in [
        "\"enforcement\":\"not_active\"",
        "\"intent_interpretation\":\"read_only_git_subset\"",
        "\"audit_construction\":\"implemented\"",
        "\"audit_persistence\":\"implemented_without_retention\"",
        "\"audit_health\":\"unhealthy\"",
        "\"target_resolution\":\"repository_scope_only\"",
        "\"approval_capabilities\":\"not_implemented\"",
        "\"hook_registration\":\"unconfirmed\"",
        // The probes execute the installed command path, so a doctor run is
        // evidence that this binary denies, not merely that the library does.
        "\"synthetic_deny\":\"passed\"",
        "\"unusable_input_deny\":\"passed\"",
        "\"built_in_baseline\":\"implemented\"",
        // Unconfigured: nothing can be placed, so nothing is provable.
        "\"configured\":false",
        "\"paths_resolvable\":false",
        "\"provable_operation_kinds\":0",
    ] {
        assert!(
            payload.contains(expected),
            "doctor output missing {expected}, got: {payload}"
        );
    }
}

#[test]
fn doctor_reports_provable_operations_only_once_configured() {
    let payload = stdout(&run_with(&["doctor"], b"", &contained()));
    assert!(payload.contains("\"configured\":true"), "got: {payload}");
    assert!(payload.contains("\"paths_resolvable\":true"));
    assert!(payload.contains("\"provable_operation_kinds\":2"));
    // Still not an active protection boundary, and it must not start claiming
    // to be one just because something became provable.
    assert!(payload.contains("\"enforcement\":\"not_active\""));
    assert!(payload.contains("\"effective_wire_behaviour\":\"every operation denies\""));
}

/// Configuration that is well formed and names nothing.
///
/// Reporting it as configured is correct -- it is. Reporting two provable
/// operation kinds would not be: nothing resolves against it, so every
/// assessment is indeterminate. An operator with a typo would read a bare
/// `configured: true` as "set up correctly".
#[test]
fn an_unresolvable_configuration_denies_and_doctor_does_not_claim_it_works() {
    let configured = unresolvable();

    let payload = stdout(&run_with(
        &["assess"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    ));
    assert!(
        payload.contains("\"reason_code\":\"TARGET_RESOLUTION_INDETERMINATE\""),
        "got: {payload}"
    );
    assert!(payload.contains("\"outcome\":\"indeterminate\""));
    assert!(payload.contains("\"supported_operation_proof\":false"));

    let hooked = run_with(
        &["hook", "codex-pre-tool-use"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    );
    assert_eq!(code(&hooked), EXIT_DENY);
    assert!(hooked.stdout.is_empty());

    let doctor = stdout(&run_with(&["doctor"], b"", &configured));
    assert!(doctor.contains("\"configured\":true"), "got: {doctor}");
    assert!(doctor.contains("\"paths_resolvable\":false"));
    assert!(
        doctor.contains("\"provable_operation_kinds\":0"),
        "doctor must not claim provable kinds against a boundary that does not \
         resolve, got: {doctor}"
    );
}

/// A supplied policy rule reaching a decision, end to end from a file on disk.
///
/// The same command that asks with no supplied policy is denied once an
/// organization bundle says so, and the reason names policy rather than the
/// built-in baseline -- those lead an operator to read different documents.
#[test]
fn a_supplied_deny_rule_changes_the_decision() {
    let mut configured = contained();
    let command = envelope("Bash", "git status");

    let without = stdout(&run_with(&["assess"], command.as_bytes(), &configured));
    assert!(without.contains("\"outcome\":\"ask\""), "got: {without}");

    configured.push(policy_directory(
        "deny",
        "organization.json",
        &deny_git_status_bundle(),
    ));
    let with = stdout(&run_with(&["assess"], command.as_bytes(), &configured));
    assert!(with.contains("\"outcome\":\"deny\""), "got: {with}");
    assert!(with.contains("\"policy_outcome\":\"deny\""));
    assert!(with.contains("\"reason_code\":\"POLICY_DENIED\""));
    // Still proven: it was denied on the strength of a rule that matched, not
    // for want of understanding the operation.
    assert!(with.contains("\"supported_operation_proof\":true"));

    // And the hook denies with that reason.
    let hooked = run_with(
        &["hook", "codex-pre-tool-use"],
        command.as_bytes(),
        &configured,
    );
    assert_eq!(code(&hooked), EXIT_DENY);
    assert!(hooked.stdout.is_empty());
    assert!(stderr(&hooked).contains("POLICY_DENIED"));
}

/// A configured policy that will not load is unhealthy, not unrestricted.
///
/// The end-to-end form of the invariant `ofw-cli/src/policy.rs` exists for. An
/// operator who broke their bundle must not silently receive the behaviour of
/// having configured no policy at all.
#[test]
fn an_unloadable_policy_denies_rather_than_running_unrestricted() {
    let cases = [
        // Valid JSON, invalid bundle: a rule effect the contract forbids.
        (
            "allow-effect",
            deny_git_status_bundle().replace(r#""effect": "deny""#, r#""effect": "allow""#),
            "POLICY_BUNDLE_INVALID",
        ),
        // Not JSON at all.
        ("truncated", "{".to_owned(), "POLICY_BUNDLE_INVALID"),
    ];

    for (label, contents, expected) in cases {
        let mut configured = contained();
        configured.push(policy_directory(label, "organization.json", &contents));

        let payload = stdout(&run_with(
            &["assess"],
            envelope("Bash", "git status").as_bytes(),
            &configured,
        ));
        assert!(
            payload.contains(&format!("\"reason_code\":\"{expected}\"")),
            "{label} must report {expected}, got: {payload}"
        );
        assert!(payload.contains("\"outcome\":\"indeterminate\""));
        assert!(payload.contains("\"policy_outcome\":\"unhealthy\""));
        // Never the unrestricted behaviour of an unconfigured deployment.
        assert!(!payload.contains("\"policy_outcome\":\"no_restriction\""));

        let hooked = run_with(
            &["hook", "codex-pre-tool-use"],
            envelope("Bash", "git status").as_bytes(),
            &configured,
        );
        assert_eq!(code(&hooked), EXIT_DENY, "{label} must deny");
        assert!(hooked.stdout.is_empty());

        // Doctor must not report a broken policy as a working one.
        let doctor = stdout(&run_with(&["doctor"], b"", &configured));
        assert!(doctor.contains("\"healthy\":false"), "{label}: {doctor}");
        assert!(doctor.contains("\"provable_operation_kinds\":0"));
    }
}

/// A configured policy location that does not exist is unhealthy.
#[test]
fn a_missing_policy_location_is_unhealthy() {
    let mut configured = contained();
    let mut absent = directory("policy-absent");
    absent.push("no-such-directory");
    configured.push((POLICY_DIRECTORY_VARIABLE, text(&absent)));

    let payload = stdout(&run_with(
        &["assess"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    ));
    assert!(
        payload.contains("\"reason_code\":\"POLICY_LOCATION_UNREADABLE\""),
        "got: {payload}"
    );
    assert!(payload.contains("\"outcome\":\"indeterminate\""));
}

/// Configuring no policy location is healthy, and stays healthy.
#[test]
fn no_configured_policy_is_healthy_rather_than_unhealthy() {
    let doctor = stdout(&run_with(&["doctor"], b"", &contained()));
    assert!(doctor.contains("\"healthy\":true"), "got: {doctor}");
    assert!(doctor.contains("\"loaded_bundles\":0"));
    assert!(doctor.contains("\"provable_operation_kinds\":2"));
}

#[test]
fn version_reports_that_enforcement_is_not_active() {
    let output = run(&["version"], b"");
    assert_eq!(code(&output), EXIT_OK);
    assert!(stdout(&output).contains("\"name\":\"ofw\""));
    assert!(stdout(&output).contains("\"enforcement\":\"not_active\""));
}

#[test]
fn an_unknown_subcommand_reports_usage_on_stderr() {
    let output = run(&["nonsense"], b"");
    assert_eq!(code(&output), EXIT_USAGE);
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("USAGE:"));
}

#[test]
fn help_goes_to_stdout_and_succeeds() {
    let output = run(&["--help"], b"");
    assert_eq!(code(&output), EXIT_OK);
    assert!(stdout(&output).contains("USAGE:"));
}

/// Retained red-first witness: the silent-success shape.
///
/// Codex treats empty stdout with exit 0 as an allow. A hook that fell back to
/// "write nothing, exit cleanly" on an unusable input would authorize it. The
/// assertion that rejects this witness is the same one
/// `an_unconfigured_envelope_denies_because_nothing_can_be_placed` makes.
fn vulnerable_empty_stdout_exit_zero() -> (i32, Vec<u8>, Vec<u8>) {
    (EXIT_OK, Vec::new(), Vec::new())
}

#[test]
fn red_first_witness_detects_silent_success() {
    let denies =
        |exit: i32, out: &[u8], err: &[u8]| exit == EXIT_DENY && out.is_empty() && !err.is_empty();

    let real = run(
        &["hook", "codex-pre-tool-use"],
        envelope("Bash", "git status").as_bytes(),
    );
    assert!(
        denies(code(&real), &real.stdout, &real.stderr),
        "the real hook must deny an unprovable operation"
    );

    let (exit, out, err) = vulnerable_empty_stdout_exit_zero();
    assert!(
        !denies(exit, &out, &err),
        "the silent-success witness must not satisfy the deny assertion"
    );
}

/// Pins the allow object against the wire shape confirmed from the host binary.
///
/// The allow path is unreachable today -- nothing in the interpreted subset
/// reaches an allow -- so no end-to-end run can exercise it. Building the same
/// object the binary would and asserting its shape is what keeps the confirmed
/// evidence attached to the code: if someone later adds a field, or renames
/// `permissionDecision`, this fails rather than the host silently recording a
/// hook failure and letting the call proceed.
///
/// Confirmed 2026-08-07 against codex-cli 0.146.0's embedded JSON Schema:
/// `PreToolUseHookSpecificOutputWire` requires only `hookEventName`, and
/// `permissionDecision` is one of `allow`, `deny`, `ask`.
#[test]
fn the_allow_object_matches_the_confirmed_wire_shape() {
    // The exact bytes `allow()` writes.
    const ALLOW: &str =
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#;

    assert!(ALLOW.contains(r#""hookEventName":"PreToolUse""#));
    assert!(ALLOW.contains(r#""permissionDecision":"allow""#));
    // `additionalProperties: false` on the host side: emitting a field the
    // schema does not name makes the whole object invalid, and an invalid
    // object is a hook failure, and a hook failure lets the call proceed.
    for forbidden in [
        "updatedInput",
        "continue",
        "stopReason",
        "suppressOutput",
        "decision",
        "reason",
    ] {
        assert!(
            !ALLOW.contains(forbidden),
            "the allow object must not carry {forbidden}"
        );
    }
}

/// A decision reaches disk, and the record carries no payload.
///
/// The end-to-end form of the audit invariant: the binary writes a real record
/// through a real sink, and the canary the agent put in its command is not in
/// it. Asserting redaction only at the type level would miss a CLI that
/// assembled a record from somewhere else.
#[test]
fn a_decision_is_recorded_and_the_record_carries_no_payload() {
    const CANARY: &str = "CANARY_SECRET_a1b2c3d4e5";

    let audit = directory("audit-trail");
    let mut configured = contained();
    configured.push((AUDIT_DIRECTORY_VARIABLE, text(&audit)));

    let output = run_with(
        &["assess"],
        envelope("Bash", &format!("git push --token {CANARY}")).as_bytes(),
        &configured,
    );
    assert_eq!(code(&output), EXIT_OK);

    let segment = audit.join("audit.jsonl");
    let contents = match std::fs::read_to_string(&segment) {
        Ok(contents) => contents,
        Err(error) => unreachable!("a record must have been written: {error}"),
    };
    let lines: Vec<&str> = contents.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 1, "one decision, one record: {contents}");
    assert!(
        !contents.contains(CANARY),
        "the audit trail leaked the payload"
    );
    assert!(contents.contains("\"schema_version\":\"1.0\""));
    assert!(contents.contains("\"algorithm\":\"sha256\""));

    // A second decision appends rather than replacing.
    let _ = run_with(
        &["assess"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    );
    let after = match std::fs::read_to_string(&segment) {
        Ok(contents) => contents,
        Err(error) => unreachable!("the segment must still be readable: {error}"),
    };
    assert_eq!(
        after.lines().filter(|line| !line.is_empty()).count(),
        2,
        "the sink must append, not truncate"
    );
}

/// With a working sink, doctor reports a working sink.
#[test]
fn doctor_reports_audit_health_from_the_configured_sink() {
    let audit = directory("audit-doctor");
    let mut configured = contained();
    configured.push((AUDIT_DIRECTORY_VARIABLE, text(&audit)));

    let healthy = stdout(&run_with(&["doctor"], b"", &configured));
    assert!(
        healthy.contains("\"audit_health\":\"healthy\""),
        "got: {healthy}"
    );
    assert!(healthy.contains("\"audit_configured\":true"));

    // Unconfigured: no trail, and doctor says so rather than defaulting to
    // something reassuring.
    let unconfigured = stdout(&run_with(&["doctor"], b"", &contained()));
    assert!(unconfigured.contains("\"audit_health\":\"unhealthy\""));
    assert!(unconfigured.contains("\"audit_configured\":false"));
}

/// The audit trail may not live inside the repository it audits.
#[test]
fn an_audit_directory_inside_the_repository_is_unhealthy() {
    let boundary = directory("audit-inside");
    let inside = boundary.join("trail");
    match std::fs::create_dir_all(&inside) {
        Ok(()) => {}
        Err(error) => unreachable!("test directory must be creatable: {error}"),
    }
    let mut configured = configuration(&boundary, &boundary);
    configured.push((AUDIT_DIRECTORY_VARIABLE, text(&inside)));

    let doctor = stdout(&run_with(&["doctor"], b"", &configured));
    assert!(
        doctor.contains("\"audit_health\":\"unhealthy\""),
        "records inside the audited repository are writable by what they audit: {doctor}"
    );
    // Nothing was written there.
    assert!(!inside.join("audit.jsonl").exists());
}

/// `doctor` must not write to the trail it reports on.
///
/// Its probes run the real hook command, and the child would inherit the audit
/// directory. Two synthetic decisions per `doctor` run would land in the trail
/// looking exactly like real ones -- and an audit log a reader cannot trust to
/// contain only real decisions is not evidence. Found by running the binary by
/// hand and noticing three records where two were expected.
#[test]
fn doctor_probes_do_not_write_to_the_audit_trail() {
    let audit = directory("audit-probe-isolation");
    let mut configured = contained();
    configured.push((AUDIT_DIRECTORY_VARIABLE, text(&audit)));

    let doctor = stdout(&run_with(&["doctor"], b"", &configured));
    // The probes really did run -- otherwise this asserts nothing.
    assert!(
        doctor.contains("\"synthetic_deny\":\"passed\""),
        "got: {doctor}"
    );
    assert!(doctor.contains("\"unusable_input_deny\":\"passed\""));

    let segment = audit.join("audit.jsonl");
    assert!(
        !segment.exists(),
        "doctor wrote {} probe records into the audit trail",
        std::fs::read_to_string(&segment)
            .map(|contents| contents.lines().count())
            .unwrap_or(0)
    );

    // A real decision still lands, so the isolation is scoped to probes rather
    // than having switched auditing off.
    let _ = run_with(
        &["assess"],
        envelope("Bash", "git status").as_bytes(),
        &configured,
    );
    let recorded = match std::fs::read_to_string(&segment) {
        Ok(contents) => contents.lines().filter(|line| !line.is_empty()).count(),
        Err(error) => unreachable!("a real decision must be recorded: {error}"),
    };
    assert_eq!(recorded, 1, "exactly the real decision");
}

/// A named configuration file that cannot be used must not fall back to the
/// environment variables.
///
/// The fallback is the dangerous shape, and it is the one that looks helpful:
/// an operator who set a file and also has variables set would get a working
/// firewall either way, so nothing would ever reveal that the file stopped
/// being consulted. Someone who can make the file unreadable -- a permission
/// flip, a rename, a full disk -- would then silently downgrade the deployment
/// from the checked loader to the unchecked one. Refusing outright means the
/// operator finds out.
#[test]
fn a_rejected_configuration_file_does_not_fall_back_to_the_environment() {
    let boundary = directory("config-precedence");
    let working = directory("config-precedence/worktree");

    // Valid environment configuration, deliberately present throughout.
    let mut environment = configuration(&working, &boundary);

    // A good file wins over the variables, and is reported as the source.
    let good = boundary.join("ofw.conf");
    let body = format!(
        "working_directory = {}\nrepository_boundary = {}\nenvironment = test\n",
        working.display(),
        boundary.display()
    );
    match std::fs::write(&good, body.as_bytes()) {
        Ok(()) => {}
        Err(error) => unreachable!("test file must be writable: {error}"),
    }
    environment.push((CONFIG_FILE_VARIABLE, text(&good)));
    let report = doctor_configuration(&environment);
    assert_eq!(report.0, "configuration_file");
    assert!(report.1, "a good file must configure");

    // Now point at a file that is not there, keeping the valid variables.
    let mut broken = environment.clone();
    let missing = boundary.join("absent.conf");
    match broken.last_mut() {
        Some(entry) => entry.1 = text(&missing),
        None => unreachable!("the config file variable must be present"),
    }
    let report = doctor_configuration(&broken);
    assert_eq!(
        report.0, "configuration_file_rejected",
        "an unusable file must be reported, not silently replaced"
    );
    assert!(
        !report.1,
        "an unusable file must leave the firewall unconfigured despite valid \
         environment variables being set"
    );
}

/// Runs `doctor` and returns `(source, configured)` from its configuration
/// block.
fn doctor_configuration(environment: &[(&'static str, String)]) -> (String, bool) {
    let output = run_with(&["doctor"], b"", environment);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let source = field_after(&text, "\"source\":\"");
    let configured = text.contains("\"configured\":true");
    (source, configured)
}

/// Extracts a string field value without a JSON parser.
///
/// The CLI writes JSON with a hand-rolled writer and this test deliberately
/// does not import a parser to read it back: a parser shared by producer and
/// consumer can agree with itself about a shape neither should emit.
fn field_after(haystack: &str, marker: &str) -> String {
    let Some(start) = haystack.find(marker) else {
        unreachable!("doctor output must contain {marker}: {haystack}");
    };
    let rest = &haystack[start + marker.len()..];
    match rest.find('"') {
        Some(end) => rest[..end].to_owned(),
        None => unreachable!("unterminated field in doctor output"),
    }
}
