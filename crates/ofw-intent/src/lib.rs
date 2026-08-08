#![forbid(unsafe_code)]

//! Closed interpretation of a shell command's *intent*.
//!
//! Nothing here executes, expands, resolves or invokes anything. The input is
//! a string of bytes that some agent proposed; this crate decides whether that
//! string is one of a small number of shapes it recognizes exactly, and
//! returns a typed description of what the operation would be.
//!
//! # Closed, not best-effort
//!
//! The tokenizer rejects input it does not fully understand rather than
//! parsing what it can. A tokenizer that skipped an operator it did not
//! recognize would report `git status` for `git status; rm -rf /`, which is
//! the single most dangerous thing an interpreter of this kind can do.
//!
//! Flags are **allowlisted per subcommand**, never denylisted. The set of git
//! flags that reach an execution surface is open-ended -- `--upload-pack`,
//! `--exec-path`, `--ext-diff`, `--textconv`, `-c`, `--config-env`, pretty
//! formats carrying directives -- so a denylist would read as coverage while
//! silently admitting the next one. Anything not named is unsupported.

mod patch;

pub use patch::{
    MAX_PATCH_BYTES, MAX_PATCH_LINES, MAX_PATCH_OPERATIONS, MAX_PATCH_PATH_BYTES,
    PatchClassification, PatchUnsupportedReason, document_digest, interpret_patch,
};

use ofw_contracts::{NamespacedName, OperationEffect};

/// The revision of the closed grammar this crate implements.
///
/// Recorded in every proof's evidence so a decision made under one grammar is
/// distinguishable from one made under another. Widening what `interpret`
/// recognizes, or changing what any recognized shape means, is a change to
/// this value: a proof carrying a revision the reader does not know about must
/// be treated as unproven rather than read under the reader's own rules.
///
/// Held at `1.0.0` through the 2026-08-07 change that moved `effect`,
/// privilege and publication into the subcommand table. Judged deliberately
/// rather than left silent: the recognized shapes were unchanged, and every
/// value the table stated was the value previously produced, so no command was
/// interpreted differently and no decision moved.
///
/// Raised to `1.1.0` on 2026-08-07 for `git log` and `git diff`, which *do*
/// widen what `interpret` recognizes — and, for the first time, introduce
/// operands. A reader holding a `1.0.0` proof cannot assume a `1.1.0` proof
/// covers the same ground, because a `1.1.0` proof may be about specific paths
/// rather than about a whole repository.
///
/// `interpreted_subset_is_pinned` pins the subset per revision, so a widening
/// cannot reach green without a bump and a bump cannot reach green without its
/// subset written out.
pub const GRAMMAR_REVISION: &str = "1.1.0";

pub const MAX_COMMAND_BYTES: usize = 65_536;
pub const MAX_TOKENS: usize = 512;
pub const MAX_TOKEN_BYTES: usize = 4_096;

/// How many pathspec operands one command may carry.
///
/// Bounded for the same reason the token count is: the resolver canonicalizes
/// each one, which is a filesystem call per operand, and an interpreter that
/// accepts an unbounded list lets a caller choose how much work a single hook
/// invocation performs inside the host's deadline.
pub const MAX_PATH_OPERANDS: usize = 64;

/// Why a command string could not be reduced to literal tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellError {
    Empty,
    CommandTooLong,
    TooManyTokens,
    TokenTooLong,
    UnterminatedQuote,
    /// A shell operator, redirection, subshell, glob or history construct.
    UnsupportedConstruct,
    /// A construct whose value is not knowable without evaluating it:
    /// parameter expansion, command substitution, arithmetic expansion.
    NonLiteralExpansion,
}

/// Splits a command into literal words, or refuses.
///
/// Several rejections are deliberately broader than POSIX requires. `#` is
/// only a comment introducer at a word boundary and `~` only expands at the
/// start of a word, but both are rejected anywhere. Over-rejecting costs a
/// command the ability to be proven -- which means it denies -- while
/// under-rejecting costs correctness of the classification. Only the first
/// error is safe to make.
pub fn tokenize(command: &str) -> Result<Vec<String>, ShellError> {
    if command.len() > MAX_COMMAND_BYTES {
        return Err(ShellError::CommandTooLong);
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut characters = command.chars();

    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' => {
                if started {
                    push_token(&mut tokens, &mut current, &mut started)?;
                }
            }
            '\'' => {
                started = true;
                loop {
                    match characters.next() {
                        Some('\'') => break,
                        Some(literal) => current.push(literal),
                        None => return Err(ShellError::UnterminatedQuote),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match characters.next() {
                        Some('"') => break,
                        // Still live inside double quotes.
                        Some('$' | '`') => return Err(ShellError::NonLiteralExpansion),
                        Some('\\') => match characters.next() {
                            Some(escaped @ ('"' | '\\' | '$' | '`')) => current.push(escaped),
                            // Any other backslash sequence inside double
                            // quotes is literal in POSIX, but accepting it
                            // would widen the grammar for no gain here.
                            Some(_) => return Err(ShellError::UnsupportedConstruct),
                            None => return Err(ShellError::UnterminatedQuote),
                        },
                        Some(literal) => current.push(literal),
                        None => return Err(ShellError::UnterminatedQuote),
                    }
                }
            }
            '\\' => {
                started = true;
                match characters.next() {
                    Some(escaped) => current.push(escaped),
                    None => return Err(ShellError::UnterminatedQuote),
                }
            }
            '$' | '`' => return Err(ShellError::NonLiteralExpansion),
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '{' | '}' | '[' | ']' | '*' | '?' | '~'
            | '!' | '#' | '\n' | '\r' | '\0' => {
                return Err(ShellError::UnsupportedConstruct);
            }
            literal => {
                started = true;
                current.push(literal);
            }
        }

        if current.len() > MAX_TOKEN_BYTES {
            return Err(ShellError::TokenTooLong);
        }
        if tokens.len() > MAX_TOKENS {
            return Err(ShellError::TooManyTokens);
        }
    }

    if started {
        push_token(&mut tokens, &mut current, &mut started)?;
    }
    if tokens.is_empty() {
        return Err(ShellError::Empty);
    }
    Ok(tokens)
}

fn push_token(
    tokens: &mut Vec<String>,
    current: &mut String,
    started: &mut bool,
) -> Result<(), ShellError> {
    if tokens.len() >= MAX_TOKENS {
        return Err(ShellError::TooManyTokens);
    }
    tokens.push(std::mem::take(current));
    *started = false;
    Ok(())
}

/// How much of an execution surface the operation carries.
///
/// There is deliberately no `None` variant. Every variant here means "an
/// execution surface is reachable", and `ofw-core` maps all of them to
/// [`ExecutionSurface::Present`](ofw_core::ExecutionSurface), which no allow row
/// survives. The enum exists to say *which* surface, because the two known ones
/// arrive by different routes and a future variant might not be reachable at
/// all — and that judgement should be made by whoever adds it, against a named
/// alternative, rather than inherited from a single-variant type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSurfaceRisk {
    /// The invoked program consults repository-controlled configuration that
    /// can name further programs to execute.
    ///
    /// Every git invocation does. `core.fsmonitor`, `core.pager`,
    /// `diff.*.textconv` and external diff drivers all name programs git will
    /// run, set in `.git/config` by the repository with no command-line flag
    /// involved. No git command can be proven non-executing from its argv alone.
    RepositoryConfigControlled,
    /// The operation writes a path that something else may later execute.
    ///
    /// Applying a patch runs no program: the host writes bytes to a file and
    /// stops. The surface is in what those bytes become. A file written to
    /// `.git/hooks/pre-commit` runs on the next commit; `.vscode/tasks.json`
    /// with `runOn: folderOpen` runs with no invocation at all; a `foo.py`
    /// dropped at a repository root shadows an installed `foo` package for
    /// every `python -m foo` launched from there, and the shadow *runs* as a
    /// side effect of the failed import before it errors.
    ///
    /// Deciding which written paths are inert would mean enumerating every
    /// convention any tool on the machine uses to find code, which is open-ended
    /// in exactly the way the flag allowlist exists to avoid being. So this is
    /// not "a patch executes something" — it is "no path can be proven inert
    /// here", which is the same shape of claim, and refused the same way.
    WrittenPathMayBeExecuted,
}

/// Whether the operation needs privilege beyond the invoking user's own, or
/// touches a security control.
///
/// One variant, like [`ExecutionSurfaceRisk`], and for the same reason: the
/// interpreted subset contains nothing else, and speculative variants invite a
/// mapping written for a case nobody has thought through. Adding one is a
/// deliberate act that breaks `ofw-core`'s exhaustive match and forces the
/// baseline consequence to be stated at the same time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegeRisk {
    /// Runs with the invoking user's own privileges and reads or writes no
    /// security control.
    Standard,
}

/// What operands a subcommand accepts, beyond its allowlisted flags.
///
/// # Why a separator is required
///
/// Git's own operand syntax is ambiguous by design: in `git log foo`, `foo` is
/// a revision if a ref of that name exists, a path if a file of that name
/// exists, and an error if both do. Git resolves this by consulting the ref
/// store and the working tree. This crate can do neither — reading `.git`
/// means reading repository-controlled state, and running git means executing
/// the thing being adjudicated.
///
/// So the ambiguity is refused rather than guessed. Only the explicit
/// `-- <pathspec>...` form is interpreted; any operand before the separator is
/// unsupported, including one that is obviously a path. That rejects plenty of
/// legitimate commands, which costs them a deny. Guessing wrong in the other
/// direction would mean resolving a revision as though it were a path, or
/// worse, treating a path as a revision and resolving nothing at all while
/// still reporting a complete resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperandGrammar {
    /// No operand of any kind. Every non-flag argument is unsupported.
    NoOperands,
    /// Pathspecs, and only following an explicit `--`.
    PathspecsAfterSeparator,
}

/// Whether the operation moves repository content across a trust boundary.
///
/// Separate from the execution surface because they fail differently: an
/// execution surface runs someone else's code here, publication sends this
/// repository's content there. `git push`, `git send-email` and
/// `git request-pull` are all publications with no execution surface of their
/// own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationRisk {
    /// Nothing leaves the repository.
    Contained,
}

/// A recognized operation, before any target resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentCandidate {
    operation_kind: NamespacedName,
    effect: OperationEffect,
    execution_surface_risk: ExecutionSurfaceRisk,
    privilege_risk: PrivilegeRisk,
    publication_risk: PublicationRisk,
    path_candidates: Vec<String>,
}

impl IntentCandidate {
    #[must_use]
    pub fn operation_kind(&self) -> &NamespacedName {
        &self.operation_kind
    }

    #[must_use]
    pub const fn effect(&self) -> OperationEffect {
        self.effect
    }

    #[must_use]
    pub const fn execution_surface_risk(&self) -> ExecutionSurfaceRisk {
        self.execution_surface_risk
    }

    #[must_use]
    pub const fn privilege_risk(&self) -> PrivilegeRisk {
        self.privilege_risk
    }

    #[must_use]
    pub const fn publication_risk(&self) -> PublicationRisk {
        self.publication_risk
    }

    #[must_use]
    pub fn path_candidates(&self) -> &[String] {
        &self.path_candidates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedReason {
    /// The program is not one this crate interprets.
    ProgramUnsupported,
    /// `git` with nothing after it.
    SubcommandMissing,
    /// An option appeared before the subcommand. Rejected wholesale: `-c`,
    /// `--exec-path` and `--config-env` all live here and all reach an
    /// execution surface, and no global option is currently needed.
    GlobalOptionRejected,
    /// A git subcommand outside the interpreted subset.
    SubcommandUnsupported,
    /// An argument not on the subcommand's allowlist. For a subcommand taking
    /// pathspecs this also covers every operand *before* the `--` separator,
    /// which is where a revision would appear: revisions are not interpreted.
    ArgumentNotAllowlisted,
    /// The same allowlisted flag appeared twice.
    ArgumentRepeated,
    /// A `--` separator on a subcommand that accepts no operands.
    SeparatorNotAccepted,
    /// More pathspecs than [`MAX_PATH_OPERANDS`].
    TooManyPathOperands,
    /// A pathspec this crate will not treat as a plain relative path.
    ///
    /// Covers git's pathspec magic (`:(exclude)`, `:!`, `:/`, `:^`) and, by the
    /// same rule, anything else containing a colon -- on Windows that is the
    /// alternate-data-stream separator, and stream evidence is not collected.
    /// An empty pathspec is refused too: git reads it as "everything", which is
    /// the opposite of what an empty operand looks like it means.
    PathspecUnsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Classification {
    Supported(Box<IntentCandidate>),
    Unsupported(UnsupportedReason),
}

/// Flags accepted for `git status`. No operand or pathspec is accepted.
const STATUS_FLAGS: [&str; 6] = ["-s", "--short", "--porcelain", "-b", "--branch", "--long"];

/// Flags accepted for `git rev-parse`. All are operand-free queries; the
/// forms that take a revision are excluded until target extraction exists.
const REV_PARSE_FLAGS: [&str; 4] = [
    "--show-toplevel",
    "--absolute-git-dir",
    "--git-dir",
    "--is-inside-work-tree",
];

/// Everything the grammar must state about one interpreted subcommand.
///
/// A table rather than literals at the construction site, because `effect`,
/// `privilege` and `publication` used to be constructor defaults: every
/// `IntentCandidate` was built as a standard-privilege, non-publishing `Read`.
/// That is correct for a read-only subset and silently wrong for the first
/// subcommand that is not one -- a `git push` added to the match arm would have
/// been classified a read, skipping the baseline's publication deny row
/// entirely, with nothing in the diff to suggest a security decision had been
/// taken. Stating them per subcommand, beside the flag allowlist, makes that
/// decision impossible to inherit by accident.
struct SubcommandProfile {
    subcommand: &'static str,
    kind: &'static str,
    allowed: &'static [&'static str],
    effect: OperationEffect,
    privilege: PrivilegeRisk,
    publication: PublicationRisk,
    operands: OperandGrammar,
}

/// The interpreted subset, in full.
///
/// `interpreted_subset_is_pinned` enumerates this table, so widening it fails a
/// test that names the grammar revision -- a subcommand cannot be added without
/// the addition being looked at.
const INTERPRETED_SUBCOMMANDS: [SubcommandProfile; 4] = [
    SubcommandProfile {
        subcommand: "status",
        kind: "git.status",
        allowed: &STATUS_FLAGS,
        effect: OperationEffect::Read,
        privilege: PrivilegeRisk::Standard,
        publication: PublicationRisk::Contained,
        operands: OperandGrammar::NoOperands,
    },
    SubcommandProfile {
        subcommand: "rev-parse",
        kind: "git.rev_parse",
        allowed: &REV_PARSE_FLAGS,
        effect: OperationEffect::Read,
        privilege: PrivilegeRisk::Standard,
        publication: PublicationRisk::Contained,
        operands: OperandGrammar::NoOperands,
    },
    SubcommandProfile {
        subcommand: "log",
        kind: "git.log",
        allowed: &LOG_FLAGS,
        effect: OperationEffect::Read,
        privilege: PrivilegeRisk::Standard,
        publication: PublicationRisk::Contained,
        operands: OperandGrammar::PathspecsAfterSeparator,
    },
    SubcommandProfile {
        subcommand: "diff",
        kind: "git.diff",
        allowed: &DIFF_FLAGS,
        effect: OperationEffect::Read,
        privilege: PrivilegeRisk::Standard,
        publication: PublicationRisk::Contained,
        operands: OperandGrammar::PathspecsAfterSeparator,
    },
];

/// Flags accepted for `git log`. All are value-free output selectors.
///
/// `-p`/`--patch` is deliberately absent. Every allow row already requires an
/// absent execution surface and git never has one, so the baseline is `ask`
/// either way and this changes no decision — but patch output is the form that
/// most directly engages `diff.*.textconv` and external diff drivers, and a
/// flag allowlist that keeps the narrower set costs nothing to keep narrow.
/// The same reasoning excludes `--format`/`--pretty`, whose values carry
/// directives.
const LOG_FLAGS: [&str; 5] = [
    "--oneline",
    "--stat",
    "--name-only",
    "--name-status",
    "--no-color",
];

/// Flags accepted for `git diff`. Value-free, and `-p` excluded as above.
const DIFF_FLAGS: [&str; 6] = [
    "--stat",
    "--name-only",
    "--name-status",
    "--cached",
    "--staged",
    "--no-color",
];

/// Recognized git subcommands that this slice does not interpret.
///
/// Naming them separately keeps "we know this command and have not done it
/// yet" distinct from "we have never heard of this", which matters for
/// diagnostics and for knowing what coverage is actually missing.
const KNOWN_UNINTERPRETED_SUBCOMMANDS: [&str; 17] = [
    "add", "branch", "checkout", "clean", "commit", "fetch", "merge", "pull", "push", "rebase",
    "reset", "restore", "rm", "show", "stash", "switch", "tag",
];

/// Classifies literal tokens as a recognized operation, or refuses.
#[must_use]
pub fn classify(tokens: &[String]) -> Classification {
    let Some(program) = tokens.first() else {
        return Classification::Unsupported(UnsupportedReason::ProgramUnsupported);
    };
    // Matched exactly. A path such as `/usr/bin/git` or `git.exe` is not
    // accepted: which binary that names is a resolver question.
    if program != "git" {
        return Classification::Unsupported(UnsupportedReason::ProgramUnsupported);
    }

    let Some(subcommand) = tokens.get(1) else {
        return Classification::Unsupported(UnsupportedReason::SubcommandMissing);
    };
    if subcommand.starts_with('-') {
        return Classification::Unsupported(UnsupportedReason::GlobalOptionRejected);
    }

    // `tokens.get(1)` succeeded, so a tail from index 2 always exists -- empty
    // when the subcommand was the last token. Written as a fallible read so the
    // guarantee is local to the line rather than inferred from the one above.
    let arguments = tokens.get(2..).unwrap_or_default();
    let Some(profile) = INTERPRETED_SUBCOMMANDS
        .iter()
        .find(|profile| profile.subcommand == subcommand.as_str())
    else {
        let _ = KNOWN_UNINTERPRETED_SUBCOMMANDS.contains(&subcommand.as_str());
        return Classification::Unsupported(UnsupportedReason::SubcommandUnsupported);
    };

    let mut seen: Vec<&str> = Vec::new();
    let mut path_candidates: Vec<String> = Vec::new();
    let mut separator_seen = false;

    for argument in arguments {
        // Everything after `--` is a pathspec, including something that looks
        // like a flag. That is git's rule and it is the safe one: treating a
        // post-separator `--stat` as a flag would silently drop a file
        // genuinely named `--stat` from the resolved target list.
        if separator_seen {
            if path_candidates.len() >= MAX_PATH_OPERANDS {
                return Classification::Unsupported(UnsupportedReason::TooManyPathOperands);
            }
            if let Err(reason) = check_pathspec(argument) {
                return Classification::Unsupported(reason);
            }
            path_candidates.push(argument.clone());
            continue;
        }

        if argument == "--" {
            match profile.operands {
                OperandGrammar::NoOperands => {
                    return Classification::Unsupported(UnsupportedReason::SeparatorNotAccepted);
                }
                OperandGrammar::PathspecsAfterSeparator => {
                    separator_seen = true;
                    continue;
                }
            }
        }

        let Some(flag) = profile
            .allowed
            .iter()
            .find(|candidate| *candidate == argument)
        else {
            return Classification::Unsupported(UnsupportedReason::ArgumentNotAllowlisted);
        };
        if seen.contains(flag) {
            return Classification::Unsupported(UnsupportedReason::ArgumentRepeated);
        }
        seen.push(flag);
    }

    let operation_kind = match NamespacedName::new(profile.kind) {
        Ok(operation_kind) => operation_kind,
        // `kind` is a compiled-in literal that satisfies the contract, so this
        // is unreachable; refusing rather than proceeding keeps the failure
        // fail-safe if the constant is ever edited badly.
        Err(_) => return Classification::Unsupported(UnsupportedReason::SubcommandUnsupported),
    };

    Classification::Supported(Box::new(IntentCandidate {
        operation_kind,
        effect: profile.effect,
        // Not table-driven, and deliberately so: this is the one property no
        // subcommand may declare itself exempt from. No git command can be
        // proven non-executing from its argv, so an author adding a subcommand
        // is not offered the chance to claim otherwise.
        execution_surface_risk: ExecutionSurfaceRisk::RepositoryConfigControlled,
        privilege_risk: profile.privilege,
        publication_risk: profile.publication,
        path_candidates,
    }))
}

/// Whether one post-separator operand is a plain relative path this crate is
/// willing to hand to the resolver.
///
/// Note what is *not* checked here: whether the path escapes the repository.
/// That is deliberately not a syntax question. `../../etc/passwd` and a symlink
/// named `docs` that points at `/etc` are the same problem, and only one of
/// them is visible in the string. Escape is decided by the resolver, on
/// canonical paths, by path component -- so this function does not try, and a
/// traversal spelling is passed through to be caught where it can actually be
/// caught.
fn check_pathspec(spec: &str) -> Result<(), UnsupportedReason> {
    if spec.is_empty() {
        return Err(UnsupportedReason::PathspecUnsupported);
    }
    // Git's pathspec magic is a prefix (`:(exclude)x`, `:!x`, `:/`, `:^x`), but
    // any colon is refused: on Windows `name:stream` addresses an alternate
    // data stream, and this milestone collects no stream evidence.
    if spec.contains(':') {
        return Err(UnsupportedReason::PathspecUnsupported);
    }
    Ok(())
}

/// Tokenizes and classifies in one step.
pub fn interpret(command: &str) -> Result<Classification, ShellError> {
    let tokens = tokenize(command)?;
    Ok(classify(&tokens))
}

#[cfg(test)]
mod tests {
    use super::{
        Classification, ExecutionSurfaceRisk, GRAMMAR_REVISION, INTERPRETED_SUBCOMMANDS,
        IntentCandidate, MAX_COMMAND_BYTES, MAX_PATH_OPERANDS, MAX_TOKEN_BYTES, MAX_TOKENS,
        OperandGrammar, PrivilegeRisk, PublicationRisk, ShellError, UnsupportedReason, classify,
        interpret, tokenize,
    };
    use ofw_contracts::OperationEffect;

    /// The interpreted subset, stated independently of the table that defines
    /// it.
    ///
    /// This test exists to fail when the subset is widened. That is its whole
    /// purpose: `effect`, `privilege` and `publication` are per-subcommand
    /// security decisions, and the failure mode being guarded is an author
    /// adding a row by copying the one above it. A `git push` copied from
    /// `git status` would claim to be a contained, standard-privilege read.
    ///
    /// Editing this test to admit a new subcommand is the intended way through
    /// -- the point is that it cannot be skipped, and that the values have to
    /// be typed out a second time where a reviewer will see them.
    ///
    /// The subset is pinned *per grammar revision* rather than alongside a
    /// separate assertion that the revision is unchanged. An earlier version
    /// asserted both independently, which inverted the incentive: widening the
    /// subset reded the test, the remedy `GRAMMAR_REVISION`'s own documentation
    /// prescribes is to bump it, and bumping it reded the same test again. The
    /// cheapest way to green was to edit the expected subset and leave the
    /// revision alone -- exactly the outcome the pin exists to prevent.
    /// Measured, not reasoned: a bump to `1.1.0` alone failed at that line.
    ///
    /// Pairing them makes the correct action the green one. A widen without a
    /// bump fails the comparison; a bump without a stated subset falls to the
    /// catch-all; a bump with its subset written out passes.
    #[test]
    fn interpreted_subset_is_pinned() {
        let declared: Vec<_> = INTERPRETED_SUBCOMMANDS
            .iter()
            .map(|profile| {
                (
                    profile.subcommand,
                    profile.kind,
                    profile.effect,
                    profile.privilege,
                    profile.publication,
                    profile.operands,
                )
            })
            .collect();

        let expected = match GRAMMAR_REVISION {
            "1.1.0" => vec![
                (
                    "status",
                    "git.status",
                    OperationEffect::Read,
                    PrivilegeRisk::Standard,
                    PublicationRisk::Contained,
                    OperandGrammar::NoOperands,
                ),
                (
                    "rev-parse",
                    "git.rev_parse",
                    OperationEffect::Read,
                    PrivilegeRisk::Standard,
                    PublicationRisk::Contained,
                    OperandGrammar::NoOperands,
                ),
                (
                    "log",
                    "git.log",
                    OperationEffect::Read,
                    PrivilegeRisk::Standard,
                    PublicationRisk::Contained,
                    OperandGrammar::PathspecsAfterSeparator,
                ),
                (
                    "diff",
                    "git.diff",
                    OperationEffect::Read,
                    PrivilegeRisk::Standard,
                    PublicationRisk::Contained,
                    OperandGrammar::PathspecsAfterSeparator,
                ),
            ],
            other => unreachable!(
                "grammar revision {other} has no pinned subset: write out what \
                 this revision interprets, one arm per revision, stating every \
                 subcommand's effect, privilege and publication explicitly"
            ),
        };

        assert_eq!(
            declared, expected,
            "widening the interpreted subset is a grammar revision and a \
             security decision per field: bump GRAMMAR_REVISION and add an arm \
             above rather than editing this one"
        );
    }

    /// Each table entry's declared values survive the trip through `classify`.
    ///
    /// What this catches is the *wiring*: a constructor that reads back a
    /// literal instead of the profile, or one that hands every subcommand the
    /// first row's values. Verified by weakening, not assumed.
    ///
    /// What it does **not** catch, measured rather than reasoned: a typo in a
    /// `subcommand` string. This test builds its command from that same field,
    /// so a misspelled row is invoked under its misspelling and passes. A dead
    /// row is caught by `interpreted_subset_is_pinned`, which spells the
    /// subcommand out independently -- that is the reason the pin restates the
    /// values rather than reading them from the table.
    ///
    /// Deliberately *not* an assertion about the execution surface: that enum
    /// has one variant, so asserting it holds would pass whatever the code did.
    #[test]
    fn every_table_entry_is_reachable_and_keeps_its_own_profile() {
        for profile in &INTERPRETED_SUBCOMMANDS {
            let command = format!("git {}", profile.subcommand);
            match interpret(&command) {
                Ok(Classification::Supported(candidate)) => {
                    assert_eq!(candidate.operation_kind().as_str(), profile.kind);
                    assert_eq!(candidate.effect(), profile.effect);
                    assert_eq!(candidate.privilege_risk(), profile.privilege);
                    assert_eq!(candidate.publication_risk(), profile.publication);
                }
                other => unreachable!("{command} must classify, got {other:?}"),
            }
        }
    }

    fn tokens(command: &str) -> Vec<String> {
        match tokenize(command) {
            Ok(tokens) => tokens,
            Err(error) => unreachable!("command must tokenize: {error:?}"),
        }
    }

    #[test]
    fn literal_words_and_quotes_tokenize() {
        assert_eq!(tokens("git status"), ["git", "status"]);
        assert_eq!(tokens("git 'status'"), ["git", "status"]);
        assert_eq!(tokens("git \"status\""), ["git", "status"]);
        assert_eq!(tokens("  git   status  "), ["git", "status"]);
        assert_eq!(tokens("git a\\ b"), ["git", "a b"]);
    }

    #[test]
    fn red_first_witness_detects_a_tokenizer_that_ignores_operators() {
        // The failure that matters: a tokenizer which splits on whitespace and
        // ignores what it does not recognize reports a clean `git status` for
        // a command that also deletes the filesystem.
        const CHAINED: &str = "git status; rm -rf /";

        assert_eq!(
            tokenize(CHAINED),
            Err(ShellError::UnsupportedConstruct),
            "a chained command must be refused, not partially parsed"
        );

        let vulnerable = vulnerable_whitespace_tokenizer(CHAINED);
        assert_eq!(vulnerable.first().map(String::as_str), Some("git"));
        assert_eq!(vulnerable.get(1).map(String::as_str), Some("status;"));
        // And the classifier would have been handed something it could not
        // have known was dangerous.
        assert!(vulnerable.len() > 2);
    }

    #[test]
    fn every_live_shell_construct_is_refused() {
        for command in [
            "git status | tee out",
            "git status && rm -rf /",
            "git status || true",
            "git status & ",
            "git status > out",
            "git status < in",
            "git $(whoami)",
            "git `whoami`",
            "git ${HOME}",
            "git \"$(whoami)\"",
            "git status\nrm -rf /",
            "git (status)",
            "git st*tus",
            "git st?tus",
            "git ~/status",
            "git !!",
            "git status # comment",
            "git [status]",
            "git {status}",
        ] {
            assert!(
                tokenize(command).is_err(),
                "must refuse to tokenize: {command}"
            );
        }
    }

    #[test]
    fn unterminated_quotes_and_bounds_are_refused() {
        assert_eq!(tokenize("git 'status"), Err(ShellError::UnterminatedQuote));
        assert_eq!(tokenize("git \"status"), Err(ShellError::UnterminatedQuote));
        assert_eq!(tokenize("git status\\"), Err(ShellError::UnterminatedQuote));
        assert_eq!(tokenize(""), Err(ShellError::Empty));
        assert_eq!(tokenize("   "), Err(ShellError::Empty));
        assert_eq!(
            tokenize(&"a".repeat(MAX_COMMAND_BYTES + 1)),
            Err(ShellError::CommandTooLong)
        );
    }

    #[test]
    fn the_supported_read_subset_classifies() {
        for command in [
            "git status",
            "git status --short",
            "git status -s -b",
            "git rev-parse --show-toplevel",
            "git rev-parse --is-inside-work-tree",
        ] {
            let classification = match interpret(command) {
                Ok(classification) => classification,
                Err(error) => unreachable!("{command} must tokenize: {error:?}"),
            };
            match classification {
                Classification::Supported(candidate) => {
                    assert_eq!(candidate.effect(), OperationEffect::Read);
                    assert_eq!(
                        candidate.execution_surface_risk(),
                        ExecutionSurfaceRisk::RepositoryConfigControlled
                    );
                    assert!(candidate.path_candidates().is_empty());
                }
                Classification::Unsupported(reason) => {
                    unreachable!("{command} must classify, got {reason:?}")
                }
            }
        }
    }

    #[test]
    fn red_first_witness_detects_an_allowlist_that_ignores_unknown_flags() {
        // `--ext-diff` makes git run a repository-configured program. A
        // classifier that dropped flags it did not recognize would treat this
        // as an ordinary read.
        let unknown_flag = tokens("git status --ext-diff");
        assert_eq!(
            classify(&unknown_flag),
            Classification::Unsupported(UnsupportedReason::ArgumentNotAllowlisted)
        );
        // The retained permissive form keeps only the flags it knows and
        // classifies the rest away.
        assert!(matches!(
            vulnerable_ignores_unknown_flags(&unknown_flag),
            Classification::Supported(_)
        ));
    }

    #[test]
    fn global_options_and_unsupported_subcommands_are_refused() {
        let cases = [
            (
                "git -c core.pager=sh status",
                UnsupportedReason::GlobalOptionRejected,
            ),
            (
                "git --exec-path=/tmp status",
                UnsupportedReason::GlobalOptionRejected,
            ),
            ("git push", UnsupportedReason::SubcommandUnsupported),
            ("git commit", UnsupportedReason::SubcommandUnsupported),
            (
                "git status --porcelain=v2",
                UnsupportedReason::ArgumentNotAllowlisted,
            ),
            ("git status src/", UnsupportedReason::ArgumentNotAllowlisted),
            ("git status -s -s", UnsupportedReason::ArgumentRepeated),
            // A subcommand taking no operands may not carry a separator
            // either: `git status --` would otherwise read as an empty
            // pathspec list and resolve as though it had been scoped.
            ("git status --", UnsupportedReason::SeparatorNotAccepted),
            // Revisions are not interpreted, so a pre-separator operand is
            // refused even when a valid pathspec follows it.
            (
                "git log HEAD -- src/main.rs",
                UnsupportedReason::ArgumentNotAllowlisted,
            ),
            // ...and the ambiguous bare form is refused outright rather than
            // guessed at, which is the whole reason the separator is required.
            (
                "git log src/main.rs",
                UnsupportedReason::ArgumentNotAllowlisted,
            ),
            (
                "git diff --stat --stat",
                UnsupportedReason::ArgumentRepeated,
            ),
            ("git log -- ''", UnsupportedReason::PathspecUnsupported),
            (
                "git log -- ':(exclude)src'",
                UnsupportedReason::PathspecUnsupported,
            ),
            ("git log -- ':!src'", UnsupportedReason::PathspecUnsupported),
            (
                "git log -- 'notes.txt:hidden'",
                UnsupportedReason::PathspecUnsupported,
            ),
            ("git", UnsupportedReason::SubcommandMissing),
            ("ls", UnsupportedReason::ProgramUnsupported),
            ("/usr/bin/git status", UnsupportedReason::ProgramUnsupported),
        ];
        for (command, expected) in cases {
            assert_eq!(
                classify(&tokens(command)),
                Classification::Unsupported(expected),
                "unexpected classification for {command}"
            );
        }
    }

    fn supported(command: &str) -> IntentCandidate {
        match interpret(command) {
            Ok(Classification::Supported(candidate)) => *candidate,
            other => unreachable!("{command} must classify, got {other:?}"),
        }
    }

    /// The token-length bound is enforced at its boundary.
    ///
    /// Added after a mutation run: replacing `>` with `==` in the length check
    /// survived every existing test. Under that mutant only a token of
    /// *exactly* `MAX_TOKEN_BYTES` is refused and everything longer is
    /// accepted, which inverts a bound into a single forbidden value. Nothing
    /// tested the boundary, so nothing noticed.
    #[test]
    fn the_token_length_bound_holds_at_its_boundary() {
        let at_limit = format!("git {}", "a".repeat(MAX_TOKEN_BYTES));
        assert!(
            tokenize(&at_limit).is_ok(),
            "a token exactly at the limit is allowed"
        );

        // One byte over is refused -- and so is far over, which is what the
        // `==` mutant lets through.
        for excess in [1, 2, MAX_TOKEN_BYTES] {
            let over = format!("git {}", "a".repeat(MAX_TOKEN_BYTES + excess));
            assert_eq!(
                tokenize(&over),
                Err(ShellError::TokenTooLong),
                "a token {excess} bytes over the limit must be refused"
            );
        }
    }

    /// The command-length bound is enforced at its boundary.
    ///
    /// Built from many long words rather than one enormous one on purpose. The
    /// obvious version -- a single token of `MAX_COMMAND_BYTES` -- is refused
    /// by `MAX_TOKEN_BYTES` first and never reaches the command-length check at
    /// all, so it would pass while constraining nothing. Same wrong-layer trap
    /// as writing a classification test whose input fails at tokenizing.
    #[test]
    fn the_command_length_bound_holds_at_its_boundary() {
        // Long enough that `MAX_TOKENS` is not reached first, short enough that
        // `MAX_TOKEN_BYTES` is not reached either.
        const WORD: usize = 4_000;
        let command_of = |total: usize| {
            let mut command = String::with_capacity(total);
            while total - command.len() > WORD + 1 {
                command.push_str(&"a".repeat(WORD));
                command.push(' ');
            }
            command.push_str(&"a".repeat(total - command.len()));
            command
        };

        let at_limit = command_of(MAX_COMMAND_BYTES);
        assert_eq!(at_limit.len(), MAX_COMMAND_BYTES, "the fixture is exact");
        assert!(
            tokenize(&at_limit).is_ok(),
            "a command exactly at the limit is allowed"
        );

        // One byte over, and far over: an `==` mutant refuses only the first of
        // these, so a single over-limit case would not notice the difference.
        for excess in [1, 2, MAX_TOKEN_BYTES] {
            assert_eq!(
                tokenize(&command_of(MAX_COMMAND_BYTES + excess)),
                Err(ShellError::CommandTooLong),
                "a command {excess} bytes over the limit must be refused"
            );
        }
    }

    /// The token-count bound is enforced at its boundary.
    #[test]
    fn the_token_count_bound_holds_at_its_boundary() {
        let words = |count: usize| {
            let mut command = String::from("git");
            for _ in 1..count {
                command.push_str(" a");
            }
            command
        };
        assert!(tokenize(&words(MAX_TOKENS)).is_ok(), "exactly the limit");
        for excess in [1, 2, 64] {
            assert_eq!(
                tokenize(&words(MAX_TOKENS + excess)),
                Err(ShellError::TooManyTokens),
                "{excess} tokens over the limit must be refused"
            );
        }

        // The same count again, with a trailing space.
        //
        // This case exists to pin which check does the work. `push_token`
        // refuses at `>=` before pushing, so the in-loop `tokens.len() >
        // MAX_TOKENS` guard below it can never be true -- that comparison is
        // unreachable, and saying so is more honest than implying it holds a
        // live path. What the trailing space changes is *where* the last token
        // is pushed: inside the loop rather than after it, so the count reaches
        // exactly `MAX_TOKENS` while the in-loop check still runs. A mutation
        // of that check to `>=` or `==` then refuses a command that is within
        // every documented bound.
        let trailing = format!("{} ", words(MAX_TOKENS));
        assert!(
            tokenize(&trailing).is_ok(),
            "exactly the limit, pushed inside the loop, is still allowed"
        );
    }

    #[test]
    fn pathspecs_are_extracted_only_after_the_separator() {
        // No operands at all: a whole-repository read, and the list is empty
        // because there was nothing to extract -- not because extraction
        // failed. The resolver distinguishes those two by the operation kind.
        assert!(supported("git log").path_candidates().is_empty());
        assert!(supported("git diff --stat").path_candidates().is_empty());

        assert_eq!(
            supported("git log -- src/main.rs").path_candidates(),
            ["src/main.rs"]
        );
        assert_eq!(
            supported("git diff --cached -- src/ docs/README.md").path_candidates(),
            ["src/", "docs/README.md"]
        );
    }

    /// After `--`, a flag-shaped operand is a path.
    ///
    /// Git's rule, and the safe one: reading a post-separator `--stat` as a
    /// flag would drop a file genuinely named `--stat` from the resolved
    /// target list, so the command would be adjudicated against fewer targets
    /// than it actually touches.
    #[test]
    fn a_flag_shaped_operand_after_the_separator_is_a_path() {
        assert_eq!(supported("git log -- --stat").path_candidates(), ["--stat"]);
        assert_eq!(supported("git log -- --").path_candidates(), ["--"]);
    }

    /// Traversal spellings are passed through, not refused here.
    ///
    /// Escape is not a syntax question: `../../etc/passwd` and a symlink named
    /// `docs` pointing at `/etc` are the same problem and only one is visible
    /// in the string. The resolver decides containment on canonical paths, so
    /// refusing traversal here would give a false impression of where the
    /// control lives while catching only the obvious half.
    #[test]
    fn traversal_is_left_for_the_resolver_to_decide() {
        assert_eq!(
            supported("git log -- ../../etc/passwd").path_candidates(),
            ["../../etc/passwd"]
        );
    }

    #[test]
    fn the_pathspec_count_is_bounded() {
        let mut command = String::from("git log --");
        for index in 0..=MAX_PATH_OPERANDS {
            command.push_str(&format!(" f{index}"));
        }
        assert_eq!(
            interpret(&command),
            Ok(Classification::Unsupported(
                UnsupportedReason::TooManyPathOperands
            ))
        );
    }

    /// Retained red-first witness: whitespace-only splitting.
    fn vulnerable_whitespace_tokenizer(command: &str) -> Vec<String> {
        command
            .split_whitespace()
            .map(std::string::ToString::to_string)
            .collect()
    }

    /// Retained red-first witness: an allowlist that silently drops arguments
    /// it does not recognize instead of refusing the command.
    fn vulnerable_ignores_unknown_flags(tokens: &[String]) -> Classification {
        let kept: Vec<String> = tokens
            .iter()
            .filter(|token| !token.starts_with("--ext"))
            .cloned()
            .collect();
        classify(&kept)
    }
}
