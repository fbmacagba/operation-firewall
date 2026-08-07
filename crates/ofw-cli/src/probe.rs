//! Diagnostic probes that execute the installed hook command path.
//!
//! The design requires doctor's probes to run the real installed command
//! rather than call the pipeline in process. The distinction is the entire
//! value of the check: an in-process call proves the library denies, which is
//! already covered by tests. What an operator needs to know is whether the
//! binary **on this machine, at this path, launched the way the host launches
//! it** denies -- which also covers a truncated install, a shim that swallows
//! the exit code, a wrapper script that rewrites stdout, and a binary built
//! from different source than the tests ran against.
//!
//! Every probe asserts the fail-closed direction. There is no probe that
//! expects an allow, because nothing in the interpreted subset reaches one; a
//! probe written to expect an allow today would have to be written to accept a
//! deny, and would then pass for either.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// The self-imposed bound on one probe.
///
/// A probe that hangs must not hang `doctor`. Exceeding it is a failed probe,
/// not a skipped one: a hook that does not answer in time is a hook the host
/// will treat as failed, and the host fails open.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// A synthetic envelope carrying a command the interpreter must refuse.
///
/// `git status; rm -rf /` is chosen because a tokenizer that skipped the
/// operator would report a harmless `git status`. If this probe ever passes for
/// the wrong reason, the reason code says which.
const REFUSAL_ENVELOPE: &str = concat!(
    r#"{"session_id":"ofw-doctor","transcript_path":null,"cwd":".","#,
    r#""hook_event_name":"PreToolUse","model":"doctor","turn_id":"probe","#,
    r#""permission_mode":"default","tool_name":"Bash","tool_use_id":"probe-1","#,
    r#""tool_input":{"command":"git status; rm -rf /"}}"#
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeResult {
    /// The installed path behaved as the host protocol requires.
    Passed,
    /// It answered, and not the way it must.
    Failed,
    /// It could not be run at all.
    Unavailable,
}

impl ProbeResult {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Runs the deny probes against this executable's own path.
///
/// Returns `(synthetic_deny, unusable_input)`.
#[must_use]
pub fn run_deny_probes() -> (ProbeResult, ProbeResult) {
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return (ProbeResult::Unavailable, ProbeResult::Unavailable),
    };

    let synthetic = probe_denies(&executable, REFUSAL_ENVELOPE.as_bytes());
    // Empty stdin is the case the host reads as a clean allow if the hook
    // exits 0 without writing. It is the single most important thing to
    // confirm about an installed binary.
    let unusable = probe_denies(&executable, b"");
    (synthetic, unusable)
}

/// Confirms one invocation denies the way the wire requires.
///
/// "Denies" is the full protocol condition, not just the exit code: exit 2
/// **and** completely empty stdout **and** a reason on stderr. A binary that
/// exits 2 while printing a partial JSON object to stdout would satisfy a
/// weaker check and still risk being read as a malformed decision.
fn probe_denies(executable: &std::path::Path, input: &[u8]) -> ProbeResult {
    let mut child = match Command::new(executable)
        .args(["hook", "codex-pre-tool-use"])
        // A probe must not write to the evidence store. The child inherits
        // this process's environment, so without this it would append two
        // synthetic decisions to the audit trail on every `doctor` run --
        // records that are indistinguishable from real ones to anyone reading
        // the log later, which is precisely the confusion an audit trail
        // exists to prevent. A diagnostic that contaminates the evidence it
        // reports on is worse than no diagnostic.
        .env_remove(crate::AUDIT_DIRECTORY_VARIABLE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return ProbeResult::Unavailable,
    };

    if let Some(mut handle) = child.stdin.take() {
        // A broken pipe is not a failure: the child may have already decided.
        let _ = handle.write_all(input);
    }

    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    return ProbeResult::Failed;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return ProbeResult::Unavailable,
        }
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(_) => return ProbeResult::Unavailable,
    };

    let denied = output.status.code() == Some(crate::EXIT_DENY)
        && output.stdout.is_empty()
        && !output.stderr.is_empty();
    if denied {
        ProbeResult::Passed
    } else {
        ProbeResult::Failed
    }
}
