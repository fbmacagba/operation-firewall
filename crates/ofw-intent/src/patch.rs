//! Closed interpretation of one apply-patch document.
//!
//! Same posture as the shell grammar beside it: nothing here applies, writes,
//! resolves or executes anything. The input is a string some agent proposed,
//! and this module decides whether it is exactly one of the shapes the design's
//! apply-patch subset names — a single bounded `Begin Patch`/`End Patch`
//! document of Add, Update, Delete and Move operations — returning a typed
//! description of what applying it *would* do.
//!
//! # What is refused, and why the list is a whitelist
//!
//! Every directive is matched against a closed table. A patch parser that
//! skipped a header it did not recognize would be the same defect as a
//! tokenizer that skipped an operator: the skipped line is the one that says
//! what the operation does.
//!
//! # Traversal is refused *here*, unlike everywhere else
//!
//! The rest of this project deliberately does not refuse `..` in the grammar —
//! escape is decided on canonical paths by component, because a symlink and a
//! traversal are the same problem and only one is visible in the string.
//!
//! That rule inverts for a creation target, and this is the one place it does.
//! A path that does not exist yet cannot be canonicalized, so the resolver's
//! rule for it is "canonicalize the nearest existing parent and append the
//! validated missing components". Nothing canonicalizes the appended part, so
//! a `..` inside it would survive into the containment check as text. It has to
//! be refused before it is appended, and the grammar is where that happens.

use ofw_contracts::{Digest, OperationEffect};

use crate::{ExecutionSurfaceRisk, IntentCandidate, PrivilegeRisk, PublicationRisk};

/// The whole document, bounded before anything is parsed.
///
/// The Codex adapter bounds its tool-input field independently; this is not a
/// duplicate of that check but the grammar's own, because a caller reaching
/// this module directly must not be able to choose how much work one hook
/// invocation performs.
pub const MAX_PATCH_BYTES: usize = 262_144;

/// How many file operations one document may carry.
///
/// Matches [`MAX_PATH_OPERANDS`](crate::MAX_PATH_OPERANDS) and for the same
/// reason: the resolver canonicalizes each target, which is a filesystem call
/// per path, inside the host's deadline.
pub const MAX_PATCH_OPERATIONS: usize = 64;

/// How many lines the document may carry, header and body together.
pub const MAX_PATCH_LINES: usize = 16_384;

/// How long one path inside the document may be.
pub const MAX_PATCH_PATH_BYTES: usize = 4_096;

/// The operation kinds this grammar can produce.
const ADD_KIND: &str = "patch.add_file";
const UPDATE_KIND: &str = "patch.update_file";
const DELETE_KIND: &str = "patch.delete_file";
const MOVE_KIND: &str = "patch.move_file";

const BEGIN: &str = "*** Begin Patch";
const END: &str = "*** End Patch";
const ADD: &str = "*** Add File: ";
const UPDATE: &str = "*** Update File: ";
const DELETE: &str = "*** Delete File: ";
const MOVE: &str = "*** Move to: ";

/// Why a patch document is not interpreted.
///
/// Kept separate from [`UnsupportedReason`](crate::UnsupportedReason) rather
/// than merged into it. The two grammars refuse for disjoint reasons and a
/// combined enum would invite a match arm written for a shell command to
/// answer for a patch, or the reverse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchUnsupportedReason {
    /// Larger than [`MAX_PATCH_BYTES`], or more lines than
    /// [`MAX_PATCH_LINES`].
    DocumentTooLarge,
    /// The document does not open with `*** Begin Patch`.
    BeginMissing,
    /// The document does not close with `*** End Patch`, or carries content
    /// after it. A patch whose terminator is missing is a patch whose end was
    /// chosen by whatever the reader stopped at.
    EndMissing,
    /// A second `*** Begin Patch`, or a second `*** End Patch`.
    DirectiveRepeated,
    /// A `*** ` line that is not one of the recognized directives.
    DirectiveUnsupported,
    /// A body line belonging to no file operation.
    ContentBeforeDirective,
    /// A body line whose first character is not one this grammar reads. Bodies
    /// are ` `, `+`, `-` and `@@` lines only.
    ContentUnsupported,
    /// `*** Move to:` without an `*** Update File:` immediately before it, or
    /// two moves for one update.
    MoveWithoutSource,
    /// No file operation at all between the terminators.
    NoOperations,
    /// More than [`MAX_PATCH_OPERATIONS`] file operations.
    TooManyOperations,
    /// A path that is empty, longer than [`MAX_PATCH_PATH_BYTES`], carrying a
    /// doubled or trailing separator, or containing a colon.
    PathUnsupported,
    /// A path that does not start inside the worktree: a leading separator in
    /// either dialect, or a Windows drive prefix.
    ///
    /// Distinct from [`PathUnsupported`](Self::PathUnsupported) on purpose, and
    /// the distinction is load-bearing rather than cosmetic. Every absolute form
    /// is *also* refused by the component checks below — `/etc/passwd` splits to
    /// an empty first component, `C:/x` splits to a component containing a colon
    /// — so with one shared reason the absolute-path check is dead code that
    /// reads as protection. A mutation run found exactly that: four mutants of
    /// it survived, because removing it changed no outcome any test could see.
    ///
    /// Giving it its own reason makes it answerable for itself, and gives an
    /// operator the accurate answer rather than a true-but-unhelpful one.
    PathAbsolute,
    /// A path containing a `.` or `..` component.
    ///
    /// Refused in the grammar, unlike a pathspec — see the module note. A
    /// creation target has no canonical form to measure, so a traversal inside
    /// it would reach the containment check as text.
    PathTraversal,
    /// The same path named by two operations. Which one wins depends on
    /// application order, so the document does not have one meaning.
    PathRepeated,
    /// A compiled-in operation kind stopped satisfying the contract's name
    /// syntax.
    ///
    /// A build-time defect rather than anything a document can cause, and
    /// unreachable from any input. It exists because the alternative at that
    /// call site is a panic, and a panic is exit 101 — which the Codex host
    /// reads as permission to proceed. A refusal that cannot be represented
    /// must still be a refusal.
    OperationKindUnrepresentable,
}

/// The result of interpreting one patch document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchClassification {
    Supported(Box<IntentCandidate>),
    Unsupported(PatchUnsupportedReason),
}

/// What one directive line said.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileOperation {
    Add,
    Update,
    Delete,
    Move,
}

impl FileOperation {
    /// The effect applying this operation would have.
    const fn effect(self) -> OperationEffect {
        match self {
            Self::Add => OperationEffect::Create,
            Self::Update => OperationEffect::Update,
            Self::Delete => OperationEffect::Delete,
            Self::Move => OperationEffect::Move,
        }
    }

    /// How consequential this operation is relative to the others.
    ///
    /// One tool call gets one decision, so a document mixing operations has to
    /// be characterised by a single effect — and the decision authorises the
    /// whole document, not its gentlest part. Ranked by what cannot be undone
    /// from the document alone: an add leaves prior content untouched, an
    /// update overwrites it, a move removes a path as well as writing one, and
    /// a delete removes without writing anything.
    const fn severity(self) -> u8 {
        match self {
            Self::Add => 0,
            Self::Update => 1,
            Self::Move => 2,
            Self::Delete => 3,
        }
    }

    const fn kind(self) -> &'static str {
        match self {
            Self::Add => ADD_KIND,
            Self::Update => UPDATE_KIND,
            Self::Delete => DELETE_KIND,
            Self::Move => MOVE_KIND,
        }
    }
}

/// Interprets one apply-patch document, or refuses it.
///
/// # What the returned candidate does *not* carry
///
/// The design also names line-count metadata and per-operation digests as
/// output. Those are audit-facing rather than decision-facing, and the v1 audit
/// record has no field for them, so they are not produced here. A whole-document
/// digest is available through [`document_digest`] for a caller that needs to
/// bind a decision to the exact bytes it was made about; the audit record shape
/// that would carry per-operation counts is a separate slice, and `ofw doctor`
/// reports it as absent rather than implying coverage.
#[must_use]
pub fn interpret_patch(document: &str) -> PatchClassification {
    match parse(document) {
        Err(reason) => PatchClassification::Unsupported(reason),
        Ok(parsed) => PatchClassification::Supported(Box::new(parsed)),
    }
}

/// A digest over the exact document bytes a decision was made about.
///
/// Not the patch content in any readable form: the content is sensitive and
/// nothing in this crate retains it. This exists so a later revalidation can
/// ask "is this the same document" without holding the document.
#[must_use]
pub fn document_digest(document: &str) -> Digest {
    Digest::of(document.as_bytes())
}

fn parse(document: &str) -> Result<IntentCandidate, PatchUnsupportedReason> {
    if document.len() > MAX_PATCH_BYTES {
        return Err(PatchUnsupportedReason::DocumentTooLarge);
    }

    let mut lines = document.lines();
    if lines.next() != Some(BEGIN) {
        return Err(PatchUnsupportedReason::BeginMissing);
    }

    let mut operations: Vec<(FileOperation, String)> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut terminated = false;
    let mut line_count = 1_usize;
    // Whether the previous directive was an update, which is the only thing a
    // move may attach to.
    let mut update_awaiting_move = false;

    for line in lines {
        line_count += 1;
        if line_count > MAX_PATCH_LINES {
            return Err(PatchUnsupportedReason::DocumentTooLarge);
        }
        if terminated {
            // `lines()` yields nothing for a trailing newline, so anything at
            // all here is content past the terminator.
            return Err(PatchUnsupportedReason::EndMissing);
        }

        if line == END {
            terminated = true;
            continue;
        }
        if line == BEGIN {
            return Err(PatchUnsupportedReason::DirectiveRepeated);
        }

        let Some(directive) = directive_of(line)? else {
            // Not a directive: a body line, which needs an operation to belong
            // to and a shape this grammar reads.
            if operations.is_empty() {
                return Err(PatchUnsupportedReason::ContentBeforeDirective);
            }
            if !is_body_line(line) {
                return Err(PatchUnsupportedReason::ContentUnsupported);
            }
            update_awaiting_move = false;
            continue;
        };

        let (operation, raw_path) = directive;
        if matches!(operation, FileOperation::Move) && !update_awaiting_move {
            return Err(PatchUnsupportedReason::MoveWithoutSource);
        }
        update_awaiting_move = matches!(operation, FileOperation::Update);

        let path = check_path(raw_path)?;
        if paths.iter().any(|seen| seen == &path) {
            return Err(PatchUnsupportedReason::PathRepeated);
        }
        // Bounded on paths as well as on operations, and against the same
        // limit. Paths are what cost: the resolver canonicalizes each one, and
        // a move names two. Bounding operations alone would let 64 moves ask
        // for 128 filesystem calls from a limit written for 64.
        if paths.len() >= MAX_PATCH_OPERATIONS {
            return Err(PatchUnsupportedReason::TooManyOperations);
        }

        // A move rewrites the operation it attached to rather than adding one:
        // `Update File` + `Move to` is a single move of a single file, and
        // counting it twice would let a document of 32 moves trip a bound
        // written for 64 files.
        if matches!(operation, FileOperation::Move) {
            match operations.last_mut() {
                Some(last) => last.0 = FileOperation::Move,
                None => return Err(PatchUnsupportedReason::MoveWithoutSource),
            }
        } else {
            if operations.len() >= MAX_PATCH_OPERATIONS {
                return Err(PatchUnsupportedReason::TooManyOperations);
            }
            operations.push((operation, path.clone()));
        }
        paths.push(path);
    }

    if !terminated {
        return Err(PatchUnsupportedReason::EndMissing);
    }
    if operations.is_empty() {
        return Err(PatchUnsupportedReason::NoOperations);
    }

    // The whole document gets the effect of its most consequential operation.
    let Some(dominant) = operations
        .iter()
        .map(|(operation, _)| *operation)
        .max_by_key(|operation| operation.severity())
    else {
        return Err(PatchUnsupportedReason::NoOperations);
    };

    // Not `unreachable!`. The kinds are compiled-in literals so this cannot
    // fail today, but a panic here would be exit 101, and the Codex host treats
    // anything that is not exit 2 as permission to proceed. A refusal that
    // cannot be represented must still be a refusal.
    let operation_kind = ofw_contracts::NamespacedName::new(dominant.kind())
        .map_err(|_| PatchUnsupportedReason::OperationKindUnrepresentable)?;

    Ok(IntentCandidate {
        operation_kind,
        effect: dominant.effect(),
        // Applying a patch runs nothing; what it writes may be run later, and
        // no written path can be proven inert here. See the variant's own note.
        execution_surface_risk: ExecutionSurfaceRisk::WrittenPathMayBeExecuted,
        privilege_risk: PrivilegeRisk::Standard,
        publication_risk: PublicationRisk::Contained,
        path_candidates: paths,
    })
}

/// Classifies a `*** ` line, or reports that the line is not one.
///
/// `Ok(None)` means "not a directive at all"; an unrecognised `*** ` line is an
/// error rather than a body line, because a directive this build does not
/// understand is exactly the line that says what the patch does.
fn directive_of(line: &str) -> Result<Option<(FileOperation, &str)>, PatchUnsupportedReason> {
    for (prefix, operation) in [
        (ADD, FileOperation::Add),
        (UPDATE, FileOperation::Update),
        (DELETE, FileOperation::Delete),
        (MOVE, FileOperation::Move),
    ] {
        if let Some(path) = line.strip_prefix(prefix) {
            return Ok(Some((operation, path)));
        }
    }
    if line.starts_with("*** ") || line == "***" {
        return Err(PatchUnsupportedReason::DirectiveUnsupported);
    }
    Ok(None)
}

/// Whether a non-directive line is a body shape this grammar reads.
///
/// An empty line counts: a patch body carrying a blank context line is
/// ordinary, and `lines()` yields it as `""`.
fn is_body_line(line: &str) -> bool {
    line.is_empty() || line.starts_with([' ', '+', '-']) || line.starts_with("@@")
}

/// Validates one path from a directive without touching the filesystem.
fn check_path(raw: &str) -> Result<String, PatchUnsupportedReason> {
    let path = raw.trim_end_matches('\r');
    if path.is_empty() || path.len() > MAX_PATCH_PATH_BYTES {
        return Err(PatchUnsupportedReason::PathUnsupported);
    }
    // Absolute in either dialect, plus the Windows drive form that is absolute
    // without a leading separator. A patch names paths inside the worktree; one
    // that names an absolute path has already left it, and no amount of joining
    // brings it back.
    if path.starts_with('/') || path.starts_with('\\') || has_drive_prefix(path) {
        return Err(PatchUnsupportedReason::PathAbsolute);
    }
    // Both separators are split on regardless of platform. A `..\..` written on
    // Windows is traversal on Windows, and refusing it only where `\` happens
    // to be the native separator would make the check platform-dependent for a
    // document that is not.
    for component in path.split(['/', '\\']) {
        if component == ".." || component == "." {
            return Err(PatchUnsupportedReason::PathTraversal);
        }
        if component.is_empty() {
            // A doubled separator, or a trailing one. Both make the path's
            // component list ambiguous, which is what the resolver appends.
            return Err(PatchUnsupportedReason::PathUnsupported);
        }
        if component.contains(':') {
            // Same rule as a pathspec: on Windows this is the alternate-data-
            // stream separator, and stream evidence is not collected.
            return Err(PatchUnsupportedReason::PathUnsupported);
        }
    }
    Ok(path.to_owned())
}

/// Whether the path opens with a Windows drive prefix.
///
/// UNC is not this function's job: `\\server\share` opens with a separator and
/// is caught by the check beside this one.
fn has_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    match (bytes.first(), bytes.get(1)) {
        (Some(letter), Some(b':')) => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use ofw_contracts::OperationEffect;

    use super::{
        ExecutionSurfaceRisk, FileOperation, MAX_PATCH_BYTES, MAX_PATCH_LINES,
        MAX_PATCH_OPERATIONS, MAX_PATCH_PATH_BYTES, PatchClassification, PatchUnsupportedReason,
        document_digest, interpret_patch,
    };
    use crate::IntentCandidate;

    /// Joins lines into a document body, so no fixture spells an escape.
    fn body(lines: &[&str]) -> String {
        let mut text = String::new();
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    /// Wraps body lines in the terminators, so no fixture repeats them.
    fn document(lines: &[&str]) -> String {
        let mut text = body(&["*** Begin Patch"]);
        text.push_str(&body(lines));
        text.push_str(&body(&["*** End Patch"]));
        text
    }

    fn supported(lines: &[&str]) -> IntentCandidate {
        match interpret_patch(&document(lines)) {
            PatchClassification::Supported(candidate) => *candidate,
            other => unreachable!("{lines:?} must classify, got {other:?}"),
        }
    }

    fn refused(lines: &[&str]) -> PatchUnsupportedReason {
        match interpret_patch(&document(lines)) {
            PatchClassification::Unsupported(reason) => reason,
            other => unreachable!("{lines:?} must be refused, got {other:?}"),
        }
    }

    #[test]
    fn each_file_operation_classifies_as_its_own_kind_and_effect() {
        let add: &[&str] = &["*** Add File: src/new.rs", "+fn main() {}"];
        let update: &[&str] = &["*** Update File: src/old.rs", "@@", "-a", "+b"];
        let delete: &[&str] = &["*** Delete File: src/gone.rs"];
        let moved: &[&str] = &["*** Update File: src/old.rs", "*** Move to: src/new.rs"];

        let cases: [(&[&str], &str, OperationEffect); 4] = [
            (add, "patch.add_file", OperationEffect::Create),
            (update, "patch.update_file", OperationEffect::Update),
            (delete, "patch.delete_file", OperationEffect::Delete),
            (moved, "patch.move_file", OperationEffect::Move),
        ];
        for (lines, kind, effect) in cases {
            let candidate = supported(lines);
            assert_eq!(candidate.operation_kind().as_str(), kind, "{lines:?}");
            assert_eq!(candidate.effect(), effect, "{lines:?}");
        }
    }

    /// One tool call gets one decision, so a mixed document is characterised by
    /// its most consequential operation. The decision authorises the whole
    /// document, not its gentlest part.
    #[test]
    fn a_mixed_document_takes_its_most_consequential_effect() {
        let candidate = supported(&[
            "*** Add File: a.txt",
            "+one",
            "*** Update File: b.txt",
            "@@",
            "+two",
            "*** Delete File: c.txt",
        ]);
        assert_eq!(candidate.effect(), OperationEffect::Delete);
        assert_eq!(candidate.operation_kind().as_str(), "patch.delete_file");

        // Order must not decide it: the same three operations the other way up.
        let reversed = supported(&[
            "*** Delete File: c.txt",
            "*** Update File: b.txt",
            "@@",
            "+two",
            "*** Add File: a.txt",
            "+one",
        ]);
        assert_eq!(reversed.effect(), OperationEffect::Delete);

        // ...and an add beside an update is an update, not an add.
        let gentler = supported(&[
            "*** Add File: a.txt",
            "+one",
            "*** Update File: b.txt",
            "@@",
            "+two",
        ]);
        assert_eq!(gentler.effect(), OperationEffect::Update);
    }

    #[test]
    fn every_touched_path_is_a_candidate_and_a_move_names_both() {
        let candidate = supported(&["*** Update File: old.txt", "*** Move to: new.txt"]);
        assert_eq!(candidate.path_candidates(), ["old.txt", "new.txt"]);

        let several = supported(&["*** Add File: a.txt", "+x", "*** Delete File: b/c.txt"]);
        assert_eq!(several.path_candidates(), ["a.txt", "b/c.txt"]);
    }

    /// Applying a patch runs nothing, and that is not the same as reaching no
    /// execution surface. What the patch writes may be run later -- a git hook,
    /// a `tasks.json` with `runOn: folderOpen`, a module shadowing an installed
    /// package -- and no written path can be proven inert from the document.
    ///
    /// This is what keeps the baseline's write allow row out of reach for the
    /// first effect that could otherwise satisfy it.
    #[test]
    fn a_patch_always_carries_a_reachable_execution_surface() {
        let add: &[&str] = &["*** Add File: a.txt", "+x"];
        let update: &[&str] = &["*** Update File: b.txt", "@@", "+y"];
        let delete: &[&str] = &["*** Delete File: c.txt"];
        let moved: &[&str] = &["*** Update File: d.txt", "*** Move to: e.txt"];

        for lines in [add, update, delete, moved] {
            assert_eq!(
                supported(lines).execution_surface_risk(),
                ExecutionSurfaceRisk::WrittenPathMayBeExecuted,
                "{lines:?}"
            );
        }
    }

    #[test]
    fn every_refusal_reason_is_reachable() {
        let cases: [(&[&str], PatchUnsupportedReason); 12] = [
            (
                &["*** Frobnicate File: a.txt"],
                PatchUnsupportedReason::DirectiveUnsupported,
            ),
            (
                &["+orphan content"],
                PatchUnsupportedReason::ContentBeforeDirective,
            ),
            (
                &["*** Add File: a.txt", "not a body line"],
                PatchUnsupportedReason::ContentUnsupported,
            ),
            (
                &["*** Move to: b.txt"],
                PatchUnsupportedReason::MoveWithoutSource,
            ),
            (
                &["*** Add File: a.txt", "*** Move to: b.txt"],
                PatchUnsupportedReason::MoveWithoutSource,
            ),
            (&[], PatchUnsupportedReason::NoOperations),
            (
                &["*** Begin Patch"],
                PatchUnsupportedReason::DirectiveRepeated,
            ),
            (&["*** Add File: "], PatchUnsupportedReason::PathUnsupported),
            (
                &["*** Add File: a//b.txt"],
                PatchUnsupportedReason::PathUnsupported,
            ),
            (
                &["*** Add File: a.txt:stream"],
                PatchUnsupportedReason::PathUnsupported,
            ),
            (
                &["*** Add File: ../outside.txt"],
                PatchUnsupportedReason::PathTraversal,
            ),
            (
                &["*** Add File: a.txt", "*** Delete File: a.txt"],
                PatchUnsupportedReason::PathRepeated,
            ),
        ];
        for (lines, expected) in cases {
            assert_eq!(refused(lines), expected, "{lines:?}");
        }

        // The three that cannot be expressed through `document`, because they
        // are about the terminators themselves.
        let no_begin = body(&["*** Add File: a.txt", "*** End Patch"]);
        assert_eq!(
            interpret_patch(&no_begin),
            PatchClassification::Unsupported(PatchUnsupportedReason::BeginMissing)
        );
        let no_end = body(&["*** Begin Patch", "*** Add File: a.txt"]);
        assert_eq!(
            interpret_patch(&no_end),
            PatchClassification::Unsupported(PatchUnsupportedReason::EndMissing)
        );
        let past_end = body(&[
            "*** Begin Patch",
            "*** Add File: a.txt",
            "*** End Patch",
            "trailing",
        ]);
        assert_eq!(
            interpret_patch(&past_end),
            PatchClassification::Unsupported(PatchUnsupportedReason::EndMissing)
        );

        // Exhaustive on purpose. A reason added later stops compiling here
        // until it is named, and naming it means deciding where it is asserted.
        //
        // Two are asserted elsewhere rather than in the table above:
        // `DocumentTooLarge` and `TooManyOperations` need fixtures large enough
        // that they belong beside the other boundary cases.
        //
        // One is asserted nowhere, and that is the honest state of it.
        // `OperationKindUnrepresentable` cannot be produced by any document —
        // it guards a compiled-in literal, and exists only so that a
        // build-time defect refuses instead of panicking. No test can reach it
        // without changing the literal it guards, so this match is the only
        // thing keeping it from being quietly deleted.
        let _ = |reason: PatchUnsupportedReason| match reason {
            PatchUnsupportedReason::DocumentTooLarge
            | PatchUnsupportedReason::BeginMissing
            | PatchUnsupportedReason::EndMissing
            | PatchUnsupportedReason::DirectiveRepeated
            | PatchUnsupportedReason::DirectiveUnsupported
            | PatchUnsupportedReason::ContentBeforeDirective
            | PatchUnsupportedReason::ContentUnsupported
            | PatchUnsupportedReason::MoveWithoutSource
            | PatchUnsupportedReason::NoOperations
            | PatchUnsupportedReason::TooManyOperations
            | PatchUnsupportedReason::PathUnsupported
            | PatchUnsupportedReason::PathAbsolute
            | PatchUnsupportedReason::PathTraversal
            | PatchUnsupportedReason::PathRepeated
            | PatchUnsupportedReason::OperationKindUnrepresentable => {}
        };
    }

    /// Every absolute form is refused *as absolute*, not incidentally.
    ///
    /// Added after a mutation run left four survivors here. Each of these paths
    /// is also caught by the component checks further down — `/etc/passwd`
    /// splits to an empty first component, `C:/x` splits to one containing a
    /// colon — so while both refusals shared a reason, deleting the
    /// absolute-path check entirely changed nothing any test could observe. It
    /// read as protection and was dead code.
    ///
    /// Asserting the specific reason is what makes it answerable for itself.
    /// The three forms are asserted separately because they are three separate
    /// conditions, and an `||` chain is satisfied by any one of them.
    #[test]
    fn every_absolute_form_is_refused_as_absolute() {
        let cases: [&[&str]; 6] = [
            &["*** Add File: /etc/passwd"],
            &["*** Add File: \\windows\\system32\\x"],
            // UNC, which opens with a separator rather than a drive letter.
            &["*** Add File: \\\\server\\share\\x"],
            &["*** Add File: C:/windows/system32/x"],
            // Drive-relative: absolute in the drive sense with no separator at
            // all, which is the form a leading-separator check alone misses.
            &["*** Delete File: C:x"],
            &["*** Update File: ok.txt", "*** Move to: /etc/cron.d/job"],
        ];
        for lines in cases {
            assert_eq!(
                refused(lines),
                PatchUnsupportedReason::PathAbsolute,
                "{lines:?}"
            );
        }

        // ...and a relative path that merely *contains* a colon is refused for
        // its own reason, so the two are not one check wearing two names.
        assert_eq!(
            refused(&["*** Add File: notes.txt:stream"]),
            PatchUnsupportedReason::PathUnsupported
        );
    }

    /// Traversal is refused by *this* grammar, unlike a pathspec, and in both
    /// separator dialects regardless of the platform running the test.
    ///
    /// The asymmetry is deliberate and narrow: a creation target has no
    /// canonical form, so the resolver appends its components as text and
    /// nothing downstream can resolve a `..` away. Elsewhere in this project
    /// traversal is left to the resolver on purpose, because a symlink and a
    /// `..` are the same escape and only one is visible in the string.
    #[test]
    fn traversal_is_refused_in_either_separator_dialect() {
        let cases: [&[&str]; 7] = [
            &["*** Add File: ../a.txt"],
            &["*** Add File: ..\\a.txt"],
            &["*** Add File: src/../../a.txt"],
            &["*** Add File: src\\..\\..\\a.txt"],
            &["*** Add File: ./a.txt"],
            &["*** Delete File: src/./a.txt"],
            &["*** Update File: ok.txt", "*** Move to: ../escape.txt"],
        ];
        for lines in cases {
            assert_eq!(
                refused(lines),
                PatchUnsupportedReason::PathTraversal,
                "{lines:?}"
            );
        }
    }

    #[test]
    fn the_operation_bound_holds_at_its_boundary() {
        let adds = |count: usize| {
            let mut lines = Vec::new();
            for index in 0..count {
                lines.push(format!("*** Add File: file{index}.txt"));
                lines.push("+x".to_owned());
            }
            let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
            document(&borrowed)
        };
        assert!(
            matches!(
                interpret_patch(&adds(MAX_PATCH_OPERATIONS)),
                PatchClassification::Supported(_)
            ),
            "exactly the limit is accepted"
        );
        for excess in [1, 2, MAX_PATCH_OPERATIONS] {
            assert_eq!(
                interpret_patch(&adds(MAX_PATCH_OPERATIONS + excess)),
                PatchClassification::Unsupported(PatchUnsupportedReason::TooManyOperations),
                "{excess} operations over the limit must be refused"
            );
        }

        // A move names two paths, so the same limit is reached in half as many
        // operations. Bounding operations alone would have let this through.
        let moves = |count: usize| {
            let mut lines = Vec::new();
            for index in 0..count {
                lines.push(format!("*** Update File: old{index}.txt"));
                lines.push(format!("*** Move to: new{index}.txt"));
            }
            let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
            document(&borrowed)
        };
        assert!(
            matches!(
                interpret_patch(&moves(MAX_PATCH_OPERATIONS / 2)),
                PatchClassification::Supported(_)
            ),
            "exactly the limit in paths is accepted"
        );
        assert_eq!(
            interpret_patch(&moves(MAX_PATCH_OPERATIONS / 2 + 1)),
            PatchClassification::Unsupported(PatchUnsupportedReason::TooManyOperations)
        );
    }

    #[test]
    fn the_path_length_bound_holds_at_its_boundary() {
        let sized = |length: usize| {
            let directive = format!("*** Add File: {}", "a".repeat(length));
            document(&[directive.as_str(), "+x"])
        };
        assert!(
            matches!(
                interpret_patch(&sized(MAX_PATCH_PATH_BYTES)),
                PatchClassification::Supported(_)
            ),
            "a path of exactly the limit is accepted"
        );
        for excess in [1, 2, MAX_PATCH_PATH_BYTES] {
            assert_eq!(
                interpret_patch(&sized(MAX_PATCH_PATH_BYTES + excess)),
                PatchClassification::Unsupported(PatchUnsupportedReason::PathUnsupported),
                "a path {excess} bytes over the limit must be refused"
            );
        }
    }

    #[test]
    fn the_document_bounds_hold_at_their_boundaries() {
        // Byte bound. Padded inside one body line, which is ignored, so the
        // document stays valid at every size.
        let sized = |total: usize| {
            let fixed = document(&["*** Add File: a.txt", "+"]).len();
            let padding = "x".repeat(total - fixed);
            let line = format!("+{padding}");
            document(&["*** Add File: a.txt", line.as_str()])
        };
        let at_limit = sized(MAX_PATCH_BYTES);
        assert_eq!(at_limit.len(), MAX_PATCH_BYTES, "the fixture is exact");
        assert!(
            matches!(
                interpret_patch(&at_limit),
                PatchClassification::Supported(_)
            ),
            "a document of exactly the limit is accepted"
        );
        for excess in [1, 2, 4_096] {
            assert_eq!(
                interpret_patch(&sized(MAX_PATCH_BYTES + excess)),
                PatchClassification::Unsupported(PatchUnsupportedReason::DocumentTooLarge),
                "a document {excess} bytes over the limit must be refused"
            );
        }

        // Line bound, counted independently: a document of many short lines is
        // far under the byte limit and still unbounded work.
        let many_lines = |count: usize| {
            let mut lines = vec!["*** Add File: a.txt".to_owned()];
            for _ in 0..count {
                lines.push("+x".to_owned());
            }
            let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
            document(&borrowed)
        };
        // Three lines are the two terminators and the directive.
        assert!(
            matches!(
                interpret_patch(&many_lines(MAX_PATCH_LINES - 3)),
                PatchClassification::Supported(_)
            ),
            "exactly the line limit is accepted"
        );
        for excess in [1, 2, 1_024] {
            assert_eq!(
                interpret_patch(&many_lines(MAX_PATCH_LINES - 3 + excess)),
                PatchClassification::Unsupported(PatchUnsupportedReason::DocumentTooLarge),
                "{excess} lines over the limit must be refused"
            );
        }
    }

    /// The digest binds a decision to exact bytes without retaining them.
    #[test]
    fn the_document_digest_distinguishes_documents_without_carrying_them() {
        const CANARY: &str = "CANARY_SECRET_a1b2c3d4e5";
        let secret = format!("+{CANARY}");
        let one = document(&["*** Add File: a.txt", secret.as_str()]);
        let other = document(&["*** Add File: a.txt", "+harmless"]);

        let digest = document_digest(&one);
        assert_ne!(digest, document_digest(&other));
        // Stable across calls, or it could not identify anything.
        let recomputed = document_digest(&one.clone());
        assert_eq!(digest, recomputed);
        assert!(!digest.value().contains(CANARY));

        // ...and the candidate built from it carries no content either.
        let candidate = supported(&["*** Add File: a.txt", secret.as_str()]);
        assert!(!format!("{candidate:?}").contains(CANARY), "Debug leaked");
    }

    /// Every operation states its own effect, kind and severity.
    ///
    /// Exhaustive on purpose: a `FileOperation` added later stops compiling
    /// here until all three are stated, so it cannot inherit another
    /// operation's consequence by omission. Severities must also stay distinct,
    /// or `max_by_key` would choose between two operations by position, which
    /// would make a mixed document's effect depend on the order it was written.
    #[test]
    fn every_file_operation_states_its_own_consequence() {
        let all = [
            FileOperation::Add,
            FileOperation::Update,
            FileOperation::Delete,
            FileOperation::Move,
        ];
        let mut severities = Vec::new();
        for operation in all {
            match operation {
                FileOperation::Add
                | FileOperation::Update
                | FileOperation::Delete
                | FileOperation::Move => {}
            }
            assert!(!operation.kind().is_empty());
            assert_ne!(
                operation.effect(),
                OperationEffect::Read,
                "a patch never reads"
            );
            severities.push(operation.severity());
        }
        severities.sort_unstable();
        let mut distinct = severities.clone();
        distinct.dedup();
        assert_eq!(distinct.len(), all.len(), "two operations share a severity");
    }

    /// Retained red-first witness: a parser that treats an unrecognised
    /// directive as ordinary body content.
    ///
    /// "Be liberal in what you accept", applied to a patch document. The line
    /// quietly skipped is the one that says what the patch does, so the witness
    /// reports a document whose real operation it never saw.
    fn vulnerable_skips_unknown_directives(document: &str) -> bool {
        let mut saw_only_an_add = false;
        for line in document.lines() {
            if line.starts_with("*** Add File: ") {
                saw_only_an_add = true;
            }
            // Every other `*** ` line is treated as content and ignored.
        }
        saw_only_an_add
    }

    #[test]
    fn red_first_witness_detects_a_parser_that_skips_unknown_directives() {
        // A document whose only *recognised* operation is a harmless add, and
        // whose real payload is a directive this build does not understand.
        let smuggled = document(&[
            "*** Add File: notes.txt",
            "+harmless",
            "*** Chmod File: id_rsa",
        ]);

        assert_eq!(
            interpret_patch(&smuggled),
            PatchClassification::Unsupported(PatchUnsupportedReason::DirectiveUnsupported)
        );
        // The retained witness reads the same document as a plain file add.
        assert!(vulnerable_skips_unknown_directives(&smuggled));
    }
}
