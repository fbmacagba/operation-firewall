#![forbid(unsafe_code)]

//! `ofw` -- the non-interactive Operation Firewall command line entry point.
//!
//! # Why the hook path is written defensively
//!
//! Codex fails **open**. Malformed stdout, empty stdout with exit 0, an output
//! field it does not recognize, a timeout, and exit 1 all resolve to the tool
//! call proceeding. Only exit 2, or an exactly-shaped deny object, blocks.
//!
//! The guarantee this binary actually provides is not "cannot crash" -- a
//! stack overflow or an allocation failure is outside any handler's reach.
//! It is narrower and checkable: **deny is the default on every code path**.
//! Argument errors, unreadable input, an oversized envelope, an unwinding
//! panic and the self-imposed deadline all converge on the same exit-2 path,
//! and no branch reaches exit 0 without an explicit allow decision.
//!
//! Deny is emitted as exit 2 with the reason on stderr, leaving stdout
//! completely empty, rather than as the JSON deny object. A partially written
//! or interrupted stdout object would be malformed, and malformed fails open;
//! an exit code cannot be partially written.

mod json;
mod pipeline;

use std::io::{Read, Write};
use std::panic;
use std::process;
use std::thread;
use std::time::Duration;

use ofw_adapter_codex::MAX_ENVELOPE_BYTES;
use ofw_core::DecisionOutcome;

use pipeline::{
    Assessment, DEADLINE_EXCEEDED, INPUT_READ_FAILED, INTERNAL_FAILURE, Reason, USAGE_INVALID,
};

const EXIT_OK: i32 = 0;
const EXIT_DENY: i32 = 2;
/// `EX_USAGE` from `sysexits.h`. Used only for developer-facing commands --
/// never in hook mode, where anything other than 0 or 2 fails open.
const EXIT_USAGE: i32 = 64;

/// Self-imposed hook deadline, far inside Codex's 600 second budget.
///
/// The only unbounded wait is reading stdin from a parent that never closes
/// it. Generous rather than tight: a deadline short enough to trip on a loaded
/// machine would manufacture denials that look like real decisions.
const HOOK_DEADLINE: Duration = Duration::from_secs(20);

const USAGE: &str = "\
ofw -- Operation Firewall

USAGE:
    ofw hook codex-pre-tool-use   Read one Codex PreToolUse envelope on stdin.
                                  Allow exits 0; every other outcome exits 2
                                  with the reason on stderr.
    ofw assess                    Read one envelope on stdin and print one
                                  structured JSON decision on stdout.
    ofw doctor                    Print adapter coverage and enforcement
                                  health as JSON.
    ofw version                   Print version information as JSON.

Operation Firewall is under active development. Intent interpretation, target
resolution, approvals and audit are not implemented, so no operation can be
proven supported and every hook invocation denies.
";

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command: Vec<&str> = arguments.iter().map(String::as_str).collect();

    match command.as_slice() {
        ["hook", "codex-pre-tool-use", rest @ ..] => run_hook(rest),
        ["assess"] => run_assess(),
        ["doctor"] => run_doctor(),
        ["version"] => run_version(),
        ["help" | "--help" | "-h"] => {
            print_usage_to(&mut std::io::stdout());
            process::exit(EXIT_OK);
        }
        _ => {
            print_usage_to(&mut std::io::stderr());
            process::exit(EXIT_USAGE);
        }
    }
}

/// Codex hook mode.
///
/// Every failure here converges on [`deny`]. In particular an unrecognized
/// argument exits 2 rather than the usage code: Codex treats anything that is
/// not exit 2 or a valid deny object as a hook failure, and a hook failure
/// lets the tool call proceed.
fn run_hook(rest: &[&str]) {
    if !rest.is_empty() {
        deny(USAGE_INVALID);
    }

    arm_deadline();

    let assessment = match panic::catch_unwind(|| {
        let input = read_bounded_stdin();
        input.map(|bytes| pipeline::assess(&bytes))
    }) {
        Ok(Ok(assessment)) => assessment,
        Ok(Err(reason)) => deny(reason),
        // An unwinding panic is one layer, not the whole guarantee. The
        // default-deny structure above is what covers the failures no handler
        // can catch.
        Err(_) => deny(INTERNAL_FAILURE),
    };

    match assessment.outcome {
        DecisionOutcome::Allow => allow(),
        // `ask` has no wire representation: the Codex docs describe it as a
        // configuration error. Milestone 2 resolves an ask inside this process
        // against a bound approval before exiting; until then it denies.
        DecisionOutcome::Ask | DecisionOutcome::Deny | DecisionOutcome::Indeterminate => {
            deny(assessment.reason)
        }
    }
}

/// Emits the explicit allow object and exits 0.
///
/// # Unconfirmed shape
///
/// The deny object is documented; an explicit allow object is not. This shape
/// is inferred from the deny form and has **not** been confirmed against a
/// live Codex. If `permissionDecision: "allow"` turns out not to be a
/// recognized value, Codex records a hook failure and the call proceeds --
/// the same visible result, reached by the wrong mechanism, which would mask
/// a real defect later. Confirming it belongs to the live-fixture spike the
/// protocol research already lists as an open item.
///
/// No `updatedInput` is ever emitted: rewriting the operation that was just
/// evaluated is its own bypass surface.
fn allow() -> ! {
    let mut inner = json::Object::new();
    inner
        .string("hookEventName", "PreToolUse")
        .string("permissionDecision", "allow");
    let mut outer = json::Object::new();
    outer.object("hookSpecificOutput", inner);

    let payload = outer.finish();
    let mut stdout = std::io::stdout();
    if stdout.write_all(payload.as_bytes()).is_err() || stdout.flush().is_err() {
        // A partial allow object is malformed, and malformed fails open. If
        // the allow cannot be written completely, deny instead.
        deny(INTERNAL_FAILURE);
    }
    process::exit(EXIT_OK)
}

/// Emits the deny reason on stderr and exits 2, leaving stdout empty.
fn deny(reason: Reason) -> ! {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{}: {}", reason.code, reason.message);
    let _ = stderr.flush();
    process::exit(EXIT_DENY)
}

/// Starts the watchdog.
///
/// Scoped to hook mode only. `assess` and `doctor` are developer-facing, have
/// no fail-open host behind them, and must not acquire a hidden time limit.
/// Every decision path calls `process::exit` immediately after writing, so the
/// watchdog cannot fire after a decision has been emitted.
fn arm_deadline() {
    thread::spawn(|| {
        thread::sleep(HOOK_DEADLINE);
        deny(DEADLINE_EXCEEDED);
    });
}

/// Reads stdin, refusing anything past the adapter's envelope bound.
///
/// Reads one byte past the limit so an oversized envelope is rejected rather
/// than silently truncated into something that might parse.
fn read_bounded_stdin() -> Result<Vec<u8>, Reason> {
    let mut buffer = Vec::new();
    let limit = u64::try_from(MAX_ENVELOPE_BYTES).unwrap_or(u64::MAX);
    let stdin = std::io::stdin();
    let mut handle = stdin.lock().take(limit.saturating_add(1));
    match handle.read_to_end(&mut buffer) {
        Ok(_) => {}
        Err(_) => return Err(INPUT_READ_FAILED),
    }
    if buffer.len() > MAX_ENVELOPE_BYTES {
        return Err(pipeline::ENVELOPE_TOO_LARGE);
    }
    Ok(buffer)
}

fn run_assess() {
    let assessment = match read_bounded_stdin() {
        Ok(input) => pipeline::assess(&input),
        Err(reason) => Assessment {
            outcome: DecisionOutcome::Indeterminate,
            reason,
            tool_name: None,
            proof_present: false,
            policy_outcome: "no_restriction",
        },
    };

    let mut decision = json::Object::new();
    decision
        .string("schema_version", "1.0")
        .string("outcome", pipeline::outcome_name(assessment.outcome))
        .string("reason_code", assessment.reason.code)
        .string("safe_message", assessment.reason.message)
        .string("tool_name", assessment.tool_name.unwrap_or("unknown"))
        .boolean("supported_operation_proof", assessment.proof_present)
        .string("policy_outcome", assessment.policy_outcome)
        .string("adapter_protocol_revision", pipeline::protocol_revision())
        .string("wire_decision", wire_decision(assessment.outcome));

    print_line(&decision.finish());
    process::exit(EXIT_OK);
}

/// What the Codex hook would emit for this outcome. `ask` and `indeterminate`
/// both deny on the wire until Milestone 2 binds approvals.
const fn wire_decision(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "allow",
        DecisionOutcome::Ask | DecisionOutcome::Deny | DecisionOutcome::Indeterminate => "deny",
    }
}

fn run_doctor() {
    let mut adapter = json::Object::new();
    adapter
        .string("id", "ofw.codex")
        .string("protocol_revision", pipeline::protocol_revision())
        .strings("supported_tools", &["Bash", "apply_patch"]);

    let mut implemented = json::Object::new();
    implemented
        .string("contracts", "implemented")
        .string("policy_evaluation", "implemented")
        .string("built_in_baseline", "implemented")
        .string("codex_envelope_parsing", "implemented")
        .string("intent_interpretation", "not_implemented")
        .string("target_resolution", "not_implemented")
        .string("audit", "not_implemented")
        .string("approval_capabilities", "not_implemented");

    let mut report = json::Object::new();
    report
        .string("schema_version", "1.0")
        .object("adapter", adapter)
        .object("components", implemented)
        .integer("provable_operation_kinds", 0)
        .string("enforcement", "not_active")
        .string("hook_registration", "unconfirmed")
        .string("effective_wire_behaviour", "every operation denies")
        .string(
            "note",
            "No operation can be proven supported, so every hook invocation \
             denies. This is a development artifact and not an active \
             protection boundary.",
        );

    print_line(&report.finish());
    process::exit(EXIT_OK);
}

fn run_version() {
    let mut version = json::Object::new();
    version
        .string("name", "ofw")
        .string("version", env!("CARGO_PKG_VERSION"))
        .string("adapter_protocol_revision", pipeline::protocol_revision())
        .string("enforcement", "not_active");
    print_line(&version.finish());
    process::exit(EXIT_OK);
}

fn print_line(payload: &str) {
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{payload}");
    let _ = stdout.flush();
}

fn print_usage_to(stream: &mut dyn Write) {
    let _ = stream.write_all(USAGE.as_bytes());
    let _ = stream.flush();
}
