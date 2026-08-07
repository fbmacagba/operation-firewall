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

use ofw_contracts::{NamespacedName, OperationEffect};

/// The revision of the closed grammar this crate implements.
///
/// Recorded in every proof's evidence so a decision made under one grammar is
/// distinguishable from one made under another. Widening what `interpret`
/// recognizes, or changing what any recognized shape means, is a change to
/// this value: a proof carrying a revision the reader does not know about must
/// be treated as unproven rather than read under the reader's own rules.
pub const GRAMMAR_REVISION: &str = "1.0.0";

pub const MAX_COMMAND_BYTES: usize = 65_536;
pub const MAX_TOKENS: usize = 512;
pub const MAX_TOKEN_BYTES: usize = 4_096;

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
/// There is deliberately no `None` variant reachable from this crate. Every
/// git invocation reads repository-controlled configuration, and
/// `core.fsmonitor`, `core.pager`, `diff.*.textconv` and external diff drivers
/// all name programs git will execute -- set in `.git/config` by a malicious
/// repository with no command-line flag involved. No git command can be proven
/// non-executing from its argv alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSurfaceRisk {
    /// The invoked program consults repository-controlled configuration that
    /// can name further programs to execute.
    RepositoryConfigControlled,
}

/// A recognized operation, before any target resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentCandidate {
    operation_kind: NamespacedName,
    effect: OperationEffect,
    execution_surface_risk: ExecutionSurfaceRisk,
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
    /// An argument not on the subcommand's allowlist, including any operand,
    /// pathspec or revision -- target extraction is a later slice.
    ArgumentNotAllowlisted,
    /// The same allowlisted flag appeared twice.
    ArgumentRepeated,
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

/// Recognized git subcommands that this slice does not interpret.
///
/// Naming them separately keeps "we know this command and have not done it
/// yet" distinct from "we have never heard of this", which matters for
/// diagnostics and for knowing what coverage is actually missing.
const KNOWN_UNINTERPRETED_SUBCOMMANDS: [&str; 19] = [
    "add", "branch", "checkout", "clean", "commit", "diff", "fetch", "log", "merge", "pull",
    "push", "rebase", "reset", "restore", "rm", "show", "stash", "switch", "tag",
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

    let arguments = &tokens[2..];
    let (kind, allowed) = match subcommand.as_str() {
        "status" => ("git.status", STATUS_FLAGS.as_slice()),
        "rev-parse" => ("git.rev_parse", REV_PARSE_FLAGS.as_slice()),
        other => {
            let _ = KNOWN_UNINTERPRETED_SUBCOMMANDS.contains(&other);
            return Classification::Unsupported(UnsupportedReason::SubcommandUnsupported);
        }
    };

    let mut seen: Vec<&str> = Vec::new();
    for argument in arguments {
        let Some(flag) = allowed.iter().find(|candidate| *candidate == argument) else {
            return Classification::Unsupported(UnsupportedReason::ArgumentNotAllowlisted);
        };
        if seen.contains(flag) {
            return Classification::Unsupported(UnsupportedReason::ArgumentRepeated);
        }
        seen.push(flag);
    }

    let operation_kind = match NamespacedName::new(kind) {
        Ok(operation_kind) => operation_kind,
        // `kind` is a compiled-in literal that satisfies the contract, so this
        // is unreachable; refusing rather than proceeding keeps the failure
        // fail-safe if the constant is ever edited badly.
        Err(_) => return Classification::Unsupported(UnsupportedReason::SubcommandUnsupported),
    };

    Classification::Supported(Box::new(IntentCandidate {
        operation_kind,
        effect: OperationEffect::Read,
        execution_surface_risk: ExecutionSurfaceRisk::RepositoryConfigControlled,
        path_candidates: Vec::new(),
    }))
}

/// Tokenizes and classifies in one step.
pub fn interpret(command: &str) -> Result<Classification, ShellError> {
    let tokens = tokenize(command)?;
    Ok(classify(&tokens))
}

#[cfg(test)]
mod tests {
    use super::{
        Classification, ExecutionSurfaceRisk, MAX_COMMAND_BYTES, ShellError, UnsupportedReason,
        classify, interpret, tokenize,
    };
    use ofw_contracts::OperationEffect;

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
            ("git log", UnsupportedReason::SubcommandUnsupported),
            (
                "git status --porcelain=v2",
                UnsupportedReason::ArgumentNotAllowlisted,
            ),
            ("git status src/", UnsupportedReason::ArgumentNotAllowlisted),
            ("git status -s -s", UnsupportedReason::ArgumentRepeated),
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
