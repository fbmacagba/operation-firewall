//! End-to-end tests that run the real `ofw` binary as a child process.
//!
//! These exercise what Codex actually observes: the exit code, the exact bytes
//! on stdout, and the bytes on stderr. Asserting on library return values
//! instead would miss the failure modes that matter here, because Codex reads
//! a malformed or unexpected stream as a hook failure and lets the tool call
//! proceed.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_ofw");

const EXIT_OK: i32 = 0;
const EXIT_DENY: i32 = 2;
const EXIT_USAGE: i32 = 64;

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

fn run(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = match Command::new(BINARY)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
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
fn a_valid_bash_envelope_denies_because_nothing_can_be_proven() {
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
        stderr(&output).contains("TARGET_RESOLUTION_UNSUPPORTED"),
        "stderr must carry the reason code, got: {}",
        stderr(&output)
    );
}

/// The observable deliverable of the intent slice: the reason code now records
/// how far down the pipeline an operation actually got, rather than reporting
/// "not interpreted" for everything.
#[test]
fn the_reason_code_records_how_far_the_pipeline_reached() {
    let cases = [
        // Interpreted successfully -- blocked one stage later, at resolution.
        (
            "git status",
            "\"reason_code\":\"TARGET_RESOLUTION_UNSUPPORTED\"",
            "\"operation_kind\":\"git.status\"",
        ),
        (
            "git rev-parse --show-toplevel",
            "\"reason_code\":\"TARGET_RESOLUTION_UNSUPPORTED\"",
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
        let payload = stdout(&run(&["assess"], envelope("Bash", command).as_bytes()));
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

    for (label, input) in cases {
        let output = run(&["hook", "codex-pre-tool-use"], &input);
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

    for arguments in [
        ["hook", "codex-pre-tool-use"].as_slice(),
        ["assess"].as_slice(),
    ] {
        let output = run(
            arguments,
            envelope("Bash", &format!("git push --token {CANARY}")).as_bytes(),
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
        "\"reason_code\":\"TARGET_RESOLUTION_UNSUPPORTED\"",
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
    let output = run(&["assess"], envelope("Bash", "git status").as_bytes());
    let payload = stdout(&output);

    // Policy restricted nothing...
    assert!(
        payload.contains("\"policy_outcome\":\"no_restriction\""),
        "expected an unrestricted policy, got: {payload}"
    );
    // ...and the decision is still not an allow.
    assert!(!payload.contains("\"outcome\":\"allow\""));
    assert!(payload.contains("\"wire_decision\":\"deny\""));
}

#[test]
fn doctor_reports_that_enforcement_is_not_active() {
    let output = run(&["doctor"], b"");
    assert_eq!(code(&output), EXIT_OK);

    let payload = stdout(&output);
    for expected in [
        "\"enforcement\":\"not_active\"",
        "\"provable_operation_kinds\":0",
        "\"intent_interpretation\":\"not_implemented\"",
        "\"hook_registration\":\"unconfirmed\"",
        "\"built_in_baseline\":\"implemented\"",
    ] {
        assert!(
            payload.contains(expected),
            "doctor output missing {expected}, got: {payload}"
        );
    }
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
/// `a_valid_bash_envelope_denies_because_nothing_can_be_proven` makes.
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
