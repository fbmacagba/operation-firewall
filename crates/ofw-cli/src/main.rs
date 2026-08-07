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

mod audit;
mod json;
mod pipeline;
mod policy;
mod probe;

use std::io::{Read, Write};
use std::panic;
use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::Duration;

use ofw_adapter_codex::MAX_ENVELOPE_BYTES;
use ofw_core::DecisionOutcome;
use ofw_resolve::TrustedConfiguration;

use policy::PolicyActivation;

use pipeline::{
    Assessment, DEADLINE_EXCEEDED, INPUT_READ_FAILED, INTERNAL_FAILURE, Reason, USAGE_INVALID,
};

/// Trusted configuration variables.
///
/// All three are required together. There is no default for any of them: a
/// defaulted working directory would be whatever launched the hook, and a
/// defaulted environment would be an assumption about consequence that nobody
/// made. Absent configuration leaves every operation unprovable, which denies.
const WORKING_DIRECTORY_VARIABLE: &str = "OFW_WORKING_DIRECTORY";
const REPOSITORY_BOUNDARY_VARIABLE: &str = "OFW_REPOSITORY_BOUNDARY";
const ENVIRONMENT_VARIABLE: &str = "OFW_ENVIRONMENT";

/// Optional. A deployment that configures no supplied policy is healthy and
/// runs on the built-in baseline alone -- policy is restriction-only, so its
/// absence changes nothing. A deployment that configures one and cannot load
/// it is unhealthy and denies.
const POLICY_DIRECTORY_VARIABLE: &str = "OFW_POLICY_DIRECTORY";

/// Optional. Absent means no audit trail, which is `unhealthy` and refuses
/// mutations -- applied rather than warned about.
pub(crate) const AUDIT_DIRECTORY_VARIABLE: &str = "OFW_AUDIT_DIRECTORY";

const EXIT_OK: i32 = 0;
pub(crate) const EXIT_DENY: i32 = 2;
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

Trusted configuration comes from the environment and has no defaults. All
three of OFW_WORKING_DIRECTORY, OFW_REPOSITORY_BOUNDARY and OFW_ENVIRONMENT
must be set, or no operation can be placed and every operation denies.

Operation Firewall is under active development. Approvals and audit are not
implemented, and the interpreted subset is read-only git, so no operation
reaches an allow and every hook invocation denies.
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
        let configuration = trusted_configuration();
        let policy = policy_activation();
        let (sink, health) = open_audit(configuration.as_ref());
        let input = read_bounded_stdin();
        input.map(|bytes| {
            let assessment = pipeline::assess(
                &bytes,
                &pipeline::AssessmentContext {
                    configuration: configuration.as_ref(),
                    policy: &policy,
                },
            );
            // Record before the process exits. A decision that was made and
            // not recorded is exactly what the audit health rule exists to
            // prevent, and every path below this exits immediately.
            let environment = configuration
                .as_ref()
                .map_or(ofw_contracts::EnvironmentClass::Unknown, |configuration| {
                    configuration.environment()
                });
            let _ = audit::record(sink.as_ref(), &assessment, environment, health);
            assessment
        })
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
/// # Confirmed shape
///
/// Verified 2026-08-07 against the JSON Schema embedded in codex-cli 0.146.0's
/// own binary, which is a primary source rather than prose about one:
/// `PreToolUseHookSpecificOutputWire` requires only `hookEventName`
/// (`const: "PreToolUse"`), and `permissionDecision` accepts `allow`. This
/// object matches. See `docs/research/codex-hook-protocol.md`.
///
/// That evidence is one version on one platform, so it dates rather than
/// settles: `assert_the_allow_object_matches_the_confirmed_wire_shape` pins
/// what this emits, and `INPUT_PROTOCOL_REVISION` is what moves when the host
/// is re-verified.
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

/// Builds the trusted configuration, or reports that none was configured.
///
/// Every field is required. A partially configured firewall is not a weaker
/// firewall here -- it is an unconfigured one, because a boundary without a
/// working directory places nothing and a working directory without a boundary
/// is measured against nothing.
fn trusted_configuration() -> Option<TrustedConfiguration> {
    let working_directory = std::env::var_os(WORKING_DIRECTORY_VARIABLE)?;
    let repository_boundary = std::env::var_os(REPOSITORY_BOUNDARY_VARIABLE)?;
    let environment = std::env::var(ENVIRONMENT_VARIABLE).ok()?;
    let environment = ofw_resolve::environment_from_label(&environment)?;

    TrustedConfiguration::new(
        PathBuf::from(working_directory),
        PathBuf::from(repository_boundary),
        environment,
    )
    .ok()
}

/// The configured audit directory, if any.
fn audit_directory() -> Option<PathBuf> {
    std::env::var_os(AUDIT_DIRECTORY_VARIABLE).map(PathBuf::from)
}

/// Opens the audit sink against the configured directory and boundary.
fn open_audit(
    configuration: Option<&TrustedConfiguration>,
) -> (Option<ofw_audit::AuditSink>, ofw_audit::AuditHealth) {
    let directory = audit_directory();
    audit::open_sink(
        directory.as_deref(),
        configuration.map(TrustedConfiguration::repository_boundary),
    )
}

fn doctor_audit_health() -> ofw_audit::AuditHealth {
    open_audit(trusted_configuration().as_ref()).1
}

const fn audit_health_name(health: ofw_audit::AuditHealth) -> &'static str {
    match health {
        ofw_audit::AuditHealth::Healthy => "healthy",
        ofw_audit::AuditHealth::Degraded => "degraded",
        ofw_audit::AuditHealth::Unhealthy => "unhealthy",
        ofw_audit::AuditHealth::Unknown => "unknown",
    }
}

/// Activates supplied policy from the configured location, if there is one.
fn policy_activation() -> PolicyActivation {
    match std::env::var_os(POLICY_DIRECTORY_VARIABLE) {
        Some(directory) => policy::activate_from_directory(&PathBuf::from(directory)),
        None => PolicyActivation::none_configured(),
    }
}

fn run_assess() {
    let configuration = trusted_configuration();
    let activation = policy_activation();
    let (sink, health) = open_audit(configuration.as_ref());
    let assessment = match read_bounded_stdin() {
        Ok(input) => {
            let assessment = pipeline::assess(
                &input,
                &pipeline::AssessmentContext {
                    configuration: configuration.as_ref(),
                    policy: &activation,
                },
            );
            let environment = configuration
                .as_ref()
                .map_or(ofw_contracts::EnvironmentClass::Unknown, |configuration| {
                    configuration.environment()
                });
            let _ = audit::record(sink.as_ref(), &assessment, environment, health);
            assessment
        }
        Err(reason) => Assessment {
            outcome: DecisionOutcome::Indeterminate,
            reason,
            audit_health: "not_applicable",
            references: pipeline::AuditReferences::unattributed_public(),
            tool_name: None,
            operation_kind: None,
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
        .string(
            "operation_kind",
            assessment.operation_kind.unwrap_or("uninterpreted"),
        )
        .boolean("supported_operation_proof", assessment.proof_present)
        .string("audit_health", assessment.audit_health)
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
        .string("intent_interpretation", "read_only_git_subset")
        .string("target_resolution", "repository_scope_only")
        .string("policy_bundle_loading", "implemented")
        .string("audit_construction", "implemented")
        .string("audit_persistence", "implemented_without_retention")
        .string("approval_capabilities", "not_implemented");

    let activation = policy_activation();
    let mut policy_report = json::Object::new();
    policy_report
        .boolean(
            "configured",
            std::env::var_os(POLICY_DIRECTORY_VARIABLE).is_some(),
        )
        .boolean("healthy", activation.is_healthy())
        .integer(
            "loaded_bundles",
            u64::try_from(activation.bundle_count()).unwrap_or(0),
        )
        .string("required_variable", POLICY_DIRECTORY_VARIABLE)
        .string(
            "scope_filtering",
            "not_implemented; every supplied bundle applies, which is \
             over-restrictive rather than under-restrictive",
        );

    // Reported as configured or not, never as its contents: the paths are
    // local filesystem layout and the diagnostics output is copied into bug
    // reports.
    //
    // Configured and usable are separate questions, and reporting only the
    // first is how diagnostics start overstating. `TrustedConfiguration::new`
    // validates shape, not existence, so a boundary containing a typo is
    // well-formed configuration against which nothing resolves.
    let configuration_state = trusted_configuration();
    let configured = configuration_state.is_some();
    let resolvable = configuration_state
        .as_ref()
        .is_some_and(TrustedConfiguration::paths_resolvable);
    let mut configuration = json::Object::new();
    configuration
        .string("source", "process_environment")
        .boolean("configured", configured)
        .boolean("paths_resolvable", resolvable)
        .strings(
            "required_variables",
            &[
                WORKING_DIRECTORY_VARIABLE,
                REPOSITORY_BOUNDARY_VARIABLE,
                ENVIRONMENT_VARIABLE,
            ],
        )
        .string(
            "limitation",
            "Provenance is not verified. The design requires a bounded \
             configuration file whose ownership and permissions are checked at \
             startup; that loader is not implemented.",
        );

    // Probes execute the installed command path rather than calling the
    // pipeline in process. An in-process call would only re-prove what the
    // tests already prove; what an operator needs is that *this binary, at
    // this path* denies.
    let (synthetic_deny, unusable_input) = probe::run_deny_probes();
    let mut probes = json::Object::new();
    probes
        .string("synthetic_deny", synthetic_deny.as_str())
        .string("unusable_input_deny", unusable_input.as_str())
        .string(
            "harmless_allow",
            "not_applicable; no operation in the interpreted subset reaches an \
             allow, so a probe expecting one would have to accept a deny and \
             would then pass either way",
        );

    let mut report = json::Object::new();
    report
        .string("schema_version", "1.0")
        .object("adapter", adapter)
        .object("components", implemented)
        .object("trusted_configuration", configuration)
        .object("policy", policy_report)
        // Provable only when the configuration is present *and* its paths
        // actually resolve. Counting on presence alone would report a typo as
        // two provable kinds while every assessment came out indeterminate.
        .integer(
            "provable_operation_kinds",
            if resolvable && activation.is_healthy() {
                2
            } else {
                0
            },
        )
        .strings("provable_operations", &["git.status", "git.rev_parse"])
        .string("enforcement", "not_active")
        // Measured by opening the configured sink, not assumed. Without a
        // configured directory there is no trail, and that is what makes a
        // mutation refuse.
        .string("audit_health", audit_health_name(doctor_audit_health()))
        .boolean("audit_configured", audit_directory().is_some())
        .string(
            "audit_note",
            "Records are appended under an exclusive lock and rotated by \
             atomic rename; a damaged trailing record is quarantined on \
             recovery and reported as degraded. Retention is deliberately not \
             implemented -- deleting audit evidence is the one operation here \
             that cannot be reviewed afterwards.",
        )
        .object("hook_probes", probes)
        .string("hook_registration", "unconfirmed")
        .string(
            "hook_registration_note",
            "Confirming host registration means reading the host's own \
             configuration, which lives outside this repository. The probes \
             above confirm the installed command path behaves; they do not \
             confirm the host is configured to call it.",
        )
        .string("effective_wire_behaviour", "every operation denies")
        .string(
            "note",
            "Read-only git operations can now be proven, but a proven git read \
             is `ask` -- no git invocation can be shown non-executing from its \
             arguments -- and `ask` denies on the wire until approvals exist. \
             This is a development artifact and not an active protection \
             boundary.",
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
