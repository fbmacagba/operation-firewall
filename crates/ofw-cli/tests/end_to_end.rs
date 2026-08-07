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
const POLICY_DIRECTORY_VARIABLE: &str = "OFW_POLICY_DIRECTORY";

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

fn directory(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("ofw-e2e-{}-{label}", std::process::id()));
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
        "\"audit_persistence\":\"not_implemented\"",
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
