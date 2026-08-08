#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeSet;

/// Exact unversioned Codex hook envelope revision implemented by this adapter.
///
/// Codex does not currently send a schema-version field. Operation Firewall
/// therefore versions this observed shape at the adapter boundary and rejects
/// every field or event variant outside this revision.
pub const INPUT_PROTOCOL_REVISION: &str = "codex.pre_tool_use/2026-07-30";
pub const OUTPUT_CONTRACT_VERSION: &str = "1.0";

pub const MAX_ENVELOPE_BYTES: usize = 256 * 1_024;
pub const MAX_JSON_NESTING_DEPTH: usize = 32;
pub const MAX_JSON_VALUES: usize = 4_096;

const MAX_FIELD_NAME_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 65_536;
const MAX_OBJECT_MEMBERS: usize = 1_024;
const MAX_ARRAY_ELEMENTS: usize = 4_096;

pub const MAX_TOOL_COMMAND_BYTES: usize = MAX_JSON_STRING_BYTES;

const REQUIRED_FIELD_COUNT: usize = 10;
const SUPPORTED_HOOK_EVENT: &str = "PreToolUse";
const SUPPORTED_TOOLS: [&str; 2] = ["Bash", "apply_patch"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonRootKind {
    Object,
    Array,
    String,
    Number,
    Boolean,
    Null,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ToolInput {
    raw_json: Box<str>,
    root_kind: JsonRootKind,
}

impl ToolInput {
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.raw_json.len()
    }

    #[must_use]
    pub const fn root_kind(&self) -> JsonRootKind {
        self.root_kind
    }
}

impl fmt::Debug for ToolInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolInput")
            .field("byte_len", &self.byte_len())
            .field("root_kind", &self.root_kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PreToolUseEnvelope {
    session_id: String,
    transcript_path: Option<String>,
    cwd: String,
    model: String,
    turn_id: String,
    permission_mode: String,
    tool_name: String,
    tool_use_id: String,
    tool_input: ToolInput,
}

impl PreToolUseEnvelope {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn transcript_path(&self) -> Option<&str> {
        self.transcript_path.as_deref()
    }

    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    #[must_use]
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    #[must_use]
    pub fn permission_mode(&self) -> &str {
        &self.permission_mode
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub fn tool_use_id(&self) -> &str {
        &self.tool_use_id
    }

    #[must_use]
    pub const fn tool_input(&self) -> &ToolInput {
        &self.tool_input
    }
}

impl fmt::Debug for PreToolUseEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreToolUseEnvelope")
            .field("session_id_present", &!self.session_id.is_empty())
            .field("transcript_path_present", &self.transcript_path.is_some())
            .field("cwd_present", &!self.cwd.is_empty())
            .field("model_present", &!self.model.is_empty())
            .field("turn_id_present", &!self.turn_id.is_empty())
            .field("permission_mode_present", &!self.permission_mode.is_empty())
            .field("tool_name", &self.tool_name)
            .field("tool_use_id_present", &!self.tool_use_id.is_empty())
            .field("tool_input", &self.tool_input)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeErrorCode {
    InputTooLarge,
    InvalidUtf8,
    InvalidJson,
    NestingTooDeep,
    TooManyJsonValues,
    TooManyContainerEntries,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidFieldType,
    EmptyField,
    FieldTooLong,
    UnsupportedProtocol,
    UnsupportedTool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeError {
    code: EnvelopeErrorCode,
    safe_message: &'static str,
}

impl EnvelopeError {
    const fn new(code: EnvelopeErrorCode, safe_message: &'static str) -> Self {
        Self { code, safe_message }
    }

    #[must_use]
    pub const fn code(&self) -> EnvelopeErrorCode {
        self.code
    }

    #[must_use]
    pub const fn safe_message(&self) -> &'static str {
        self.safe_message
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message)
    }
}

impl std::error::Error for EnvelopeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeAssessment {
    Parsed(PreToolUseEnvelope),
    Indeterminate(EnvelopeError),
}

#[derive(Clone, Eq, PartialEq)]
pub struct BashToolInput {
    command: Box<str>,
}

impl BashToolInput {
    /// Returns the literal decoded command for a dedicated shell-intent adapter.
    ///
    /// This value has not been executed, expanded, tokenized, or classified.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }
}

impl fmt::Debug for BashToolInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BashToolInput")
            .field("command_byte_len", &self.command.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApplyPatchToolInput {
    patch: Box<str>,
}

impl ApplyPatchToolInput {
    /// Returns the literal decoded patch command for a dedicated patch adapter.
    ///
    /// Patch grammar and filesystem effects have not been interpreted.
    #[must_use]
    pub fn patch(&self) -> &str {
        &self.patch
    }
}

impl fmt::Debug for ApplyPatchToolInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyPatchToolInput")
            .field("patch_byte_len", &self.patch.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtractedToolInput {
    Bash(BashToolInput),
    ApplyPatch(ApplyPatchToolInput),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolInputErrorCode {
    InvalidJson,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidFieldType,
    EmptyField,
    FieldTooLong,
    UnsupportedTool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInputError {
    code: ToolInputErrorCode,
    safe_message: &'static str,
}

impl ToolInputError {
    const fn new(code: ToolInputErrorCode, safe_message: &'static str) -> Self {
        Self { code, safe_message }
    }

    #[must_use]
    pub const fn code(&self) -> ToolInputErrorCode {
        self.code
    }

    #[must_use]
    pub const fn safe_message(&self) -> &'static str {
        self.safe_message
    }
}

impl fmt::Display for ToolInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message)
    }
}

impl std::error::Error for ToolInputError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolInputAssessment {
    Extracted(ExtractedToolInput),
    Indeterminate(ToolInputError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterError {
    Envelope(EnvelopeError),
    ToolInput(ToolInputError),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(parse_error) => parse_error.fmt(formatter),
            Self::ToolInput(extraction_error) => extraction_error.fmt(formatter),
        }
    }
}

impl std::error::Error for AdapterError {}

#[derive(Clone, Eq, PartialEq)]
pub struct ExtractedPreToolUse {
    envelope: PreToolUseEnvelope,
    tool_input: ExtractedToolInput,
}

impl ExtractedPreToolUse {
    #[must_use]
    pub const fn envelope(&self) -> &PreToolUseEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn tool_input(&self) -> &ExtractedToolInput {
        &self.tool_input
    }
}

impl fmt::Debug for ExtractedPreToolUse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtractedPreToolUse")
            .field("envelope", &self.envelope)
            .field("tool_input", &self.tool_input)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterAssessment {
    Extracted(Box<ExtractedPreToolUse>),
    Indeterminate(AdapterError),
}

impl fmt::Display for AdapterAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extracted(_) => formatter.write_str("supported tool input extracted"),
            Self::Indeterminate(assessment_error) => assessment_error.fmt(formatter),
        }
    }
}

/// Strictly validates a bounded Codex `PreToolUse` envelope.
///
/// Parsing failure, protocol drift, and unsupported tools are returned as
/// typed errors. This function never repairs, defaults, or ignores input.
pub fn parse_pre_tool_use(input: &[u8]) -> Result<PreToolUseEnvelope, EnvelopeError> {
    if input.len() > MAX_ENVELOPE_BYTES {
        return Err(error(
            EnvelopeErrorCode::InputTooLarge,
            "hook envelope exceeds the configured byte limit",
        ));
    }
    let text = core::str::from_utf8(input).map_err(|_| {
        error(
            EnvelopeErrorCode::InvalidUtf8,
            "hook envelope is not valid UTF-8",
        )
    })?;
    Parser::new(text).parse_envelope()
}

/// Converts every parser failure into an explicit indeterminate state.
#[must_use]
pub fn assess_pre_tool_use(input: &[u8]) -> EnvelopeAssessment {
    match parse_pre_tool_use(input) {
        Ok(envelope) => EnvelopeAssessment::Parsed(envelope),
        Err(parse_error) => EnvelopeAssessment::Indeterminate(parse_error),
    }
}

/// Strictly extracts the exact supported payload from a validated envelope.
///
/// Extraction does not interpret the command or prove that its operation is
/// supported. The returned wrappers are inputs to later, tool-specific intent
/// adapters and must not be treated as authorization or a policy-ready state.
#[must_use]
pub fn extract_tool_input(envelope: &PreToolUseEnvelope) -> ToolInputAssessment {
    let command = match parse_command_tool_input(&envelope.tool_input.raw_json) {
        Ok(command) => command,
        Err(extraction_error) => return ToolInputAssessment::Indeterminate(extraction_error),
    };

    let extracted = match envelope.tool_name.as_str() {
        "Bash" => ExtractedToolInput::Bash(BashToolInput {
            command: command.into_boxed_str(),
        }),
        "apply_patch" => ExtractedToolInput::ApplyPatch(ApplyPatchToolInput {
            patch: command.into_boxed_str(),
        }),
        _ => {
            return ToolInputAssessment::Indeterminate(tool_input_error(
                ToolInputErrorCode::UnsupportedTool,
                "tool is outside the supported extraction subset",
            ));
        }
    };

    ToolInputAssessment::Extracted(extracted)
}

/// Runs envelope validation and strict tool-input extraction as one fail-safe
/// boundary. Its success state means only that bounded typed extraction
/// completed; it is not an allow decision or operation-support proof.
#[must_use]
pub fn assess_supported_pre_tool_use(input: &[u8]) -> AdapterAssessment {
    let envelope = match parse_pre_tool_use(input) {
        Ok(envelope) => envelope,
        Err(parse_error) => {
            return AdapterAssessment::Indeterminate(AdapterError::Envelope(parse_error));
        }
    };

    match extract_tool_input(&envelope) {
        ToolInputAssessment::Extracted(tool_input) => {
            AdapterAssessment::Extracted(Box::new(ExtractedPreToolUse {
                envelope,
                tool_input,
            }))
        }
        ToolInputAssessment::Indeterminate(extraction_error) => {
            AdapterAssessment::Indeterminate(AdapterError::ToolInput(extraction_error))
        }
    }
}

fn tool_input_error(code: ToolInputErrorCode, safe_message: &'static str) -> ToolInputError {
    ToolInputError::new(code, safe_message)
}

fn error(code: EnvelopeErrorCode, safe_message: &'static str) -> EnvelopeError {
    EnvelopeError::new(code, safe_message)
}

#[derive(Default)]
struct EnvelopeBuilder {
    session_id: Option<String>,
    transcript_path: Option<Option<String>>,
    cwd: Option<String>,
    hook_event_name: Option<String>,
    model: Option<String>,
    turn_id: Option<String>,
    permission_mode: Option<String>,
    tool_name: Option<String>,
    tool_use_id: Option<String>,
    tool_input: Option<ToolInput>,
}

impl EnvelopeBuilder {
    fn finish(self) -> Result<PreToolUseEnvelope, EnvelopeError> {
        let session_id = required(self.session_id)?;
        let transcript_path = required(self.transcript_path)?;
        let cwd = required(self.cwd)?;
        let hook_event_name = required(self.hook_event_name)?;
        let model = required(self.model)?;
        let turn_id = required(self.turn_id)?;
        let permission_mode = required(self.permission_mode)?;
        let tool_name = required(self.tool_name)?;
        let tool_use_id = required(self.tool_use_id)?;
        let tool_input = required(self.tool_input)?;

        if hook_event_name != SUPPORTED_HOOK_EVENT {
            return Err(error(
                EnvelopeErrorCode::UnsupportedProtocol,
                "hook event is outside the supported protocol revision",
            ));
        }
        if !SUPPORTED_TOOLS.contains(&tool_name.as_str()) {
            return Err(error(
                EnvelopeErrorCode::UnsupportedTool,
                "tool is outside the supported adapter subset",
            ));
        }
        if tool_input.root_kind != JsonRootKind::Object {
            return Err(error(
                EnvelopeErrorCode::InvalidFieldType,
                "tool_input must be a JSON object",
            ));
        }

        Ok(PreToolUseEnvelope {
            session_id,
            transcript_path,
            cwd,
            model,
            turn_id,
            permission_mode,
            tool_name,
            tool_use_id,
            tool_input,
        })
    }
}

fn required<T>(value: Option<T>) -> Result<T, EnvelopeError> {
    value.ok_or_else(|| {
        error(
            EnvelopeErrorCode::MissingField,
            "hook envelope is missing a required field",
        )
    })
}

fn parse_command_tool_input(input: &str) -> Result<String, ToolInputError> {
    let mut parser = Parser::new(input);
    parser.skip_whitespace();
    parser.count_value().map_err(map_tool_input_parser_error)?;
    parser
        .expect_byte(b'{')
        .map_err(map_tool_input_parser_error)?;
    parser.skip_whitespace();

    if parser.consume_byte(b'}') {
        return Err(tool_input_error(
            ToolInputErrorCode::MissingField,
            "tool input is missing the required command field",
        ));
    }

    let field = parser
        .parse_string(MAX_FIELD_NAME_BYTES)
        .map_err(map_tool_input_parser_error)?;
    if field != "command" {
        return Err(tool_input_error(
            ToolInputErrorCode::UnknownField,
            "tool input contains an unknown field",
        ));
    }

    parser.skip_whitespace();
    parser
        .expect_byte(b':')
        .map_err(map_tool_input_parser_error)?;
    parser.skip_whitespace();
    if parser.peek_byte() != Some(b'"') {
        return Err(tool_input_error(
            ToolInputErrorCode::InvalidFieldType,
            "tool input command must be a JSON string",
        ));
    }
    let command = parser
        .parse_required_string(MAX_TOOL_COMMAND_BYTES)
        .map_err(map_tool_input_parser_error)?;

    parser.skip_whitespace();
    if !parser.consume_byte(b'}') {
        parser
            .expect_byte(b',')
            .map_err(map_tool_input_parser_error)?;
        parser.skip_whitespace();
        let additional_field = parser
            .parse_string(MAX_FIELD_NAME_BYTES)
            .map_err(map_tool_input_parser_error)?;
        let (code, safe_message) = if additional_field == "command" {
            (
                ToolInputErrorCode::DuplicateField,
                "tool input contains a duplicate field",
            )
        } else {
            (
                ToolInputErrorCode::UnknownField,
                "tool input contains an unknown field",
            )
        };
        return Err(tool_input_error(code, safe_message));
    }

    parser.skip_whitespace();
    if parser.index != parser.input.len() {
        return Err(tool_input_error(
            ToolInputErrorCode::InvalidJson,
            "tool input is not valid JSON",
        ));
    }
    if command.trim().is_empty() {
        return Err(tool_input_error(
            ToolInputErrorCode::EmptyField,
            "tool input command must not be blank",
        ));
    }

    Ok(command)
}

fn map_tool_input_parser_error(parse_error: EnvelopeError) -> ToolInputError {
    match parse_error.code() {
        EnvelopeErrorCode::UnknownField => tool_input_error(
            ToolInputErrorCode::UnknownField,
            "tool input contains an unknown field",
        ),
        EnvelopeErrorCode::DuplicateField => tool_input_error(
            ToolInputErrorCode::DuplicateField,
            "tool input contains a duplicate field",
        ),
        EnvelopeErrorCode::MissingField => tool_input_error(
            ToolInputErrorCode::MissingField,
            "tool input is missing a required field",
        ),
        EnvelopeErrorCode::InvalidFieldType => tool_input_error(
            ToolInputErrorCode::InvalidFieldType,
            "tool input field has an invalid JSON type",
        ),
        EnvelopeErrorCode::EmptyField => tool_input_error(
            ToolInputErrorCode::EmptyField,
            "tool input command must not be empty",
        ),
        EnvelopeErrorCode::FieldTooLong => tool_input_error(
            ToolInputErrorCode::FieldTooLong,
            "tool input field exceeds the configured byte limit",
        ),
        _ => tool_input_error(
            ToolInputErrorCode::InvalidJson,
            "tool input is not valid JSON",
        ),
    }
}

struct Parser<'input> {
    input: &'input str,
    index: usize,
    values: usize,
}

impl<'input> Parser<'input> {
    const fn new(input: &'input str) -> Self {
        Self {
            input,
            index: 0,
            values: 0,
        }
    }

    fn parse_envelope(mut self) -> Result<PreToolUseEnvelope, EnvelopeError> {
        self.skip_whitespace();
        self.count_value()?;
        self.expect_byte(b'{')?;
        let mut fields = BTreeSet::new();
        let mut builder = EnvelopeBuilder::default();

        self.skip_whitespace();
        if self.consume_byte(b'}') {
            return Err(error(
                EnvelopeErrorCode::MissingField,
                "hook envelope is missing required fields",
            ));
        }

        loop {
            if fields.len() >= REQUIRED_FIELD_COUNT {
                return Err(error(
                    EnvelopeErrorCode::UnknownField,
                    "hook envelope contains an unknown field",
                ));
            }
            let field = self.parse_string(MAX_FIELD_NAME_BYTES)?;
            if !fields.insert(field.clone()) {
                return Err(error(
                    EnvelopeErrorCode::DuplicateField,
                    "hook envelope contains a duplicate field",
                ));
            }
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();

            match field.as_str() {
                "session_id" => {
                    builder.session_id = Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?);
                }
                "transcript_path" => {
                    builder.transcript_path = Some(self.parse_nullable_string(MAX_PATH_BYTES)?);
                }
                "cwd" => builder.cwd = Some(self.parse_required_string(MAX_PATH_BYTES)?),
                "hook_event_name" => {
                    builder.hook_event_name =
                        Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?);
                }
                "model" => builder.model = Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?),
                "turn_id" => {
                    builder.turn_id = Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?);
                }
                "permission_mode" => {
                    builder.permission_mode =
                        Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?);
                }
                "tool_name" => {
                    builder.tool_name = Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?);
                }
                "tool_use_id" => {
                    builder.tool_use_id = Some(self.parse_required_string(MAX_IDENTIFIER_BYTES)?);
                }
                "tool_input" => builder.tool_input = Some(self.parse_tool_input()?),
                _ => {
                    return Err(error(
                        EnvelopeErrorCode::UnknownField,
                        "hook envelope contains an unknown field",
                    ));
                }
            }

            self.skip_whitespace();
            if self.consume_byte(b'}') {
                break;
            }
            self.expect_byte(b',')?;
            self.skip_whitespace();
        }

        self.skip_whitespace();
        if self.index != self.input.len() {
            return Err(invalid_json());
        }
        builder.finish()
    }

    fn parse_tool_input(&mut self) -> Result<ToolInput, EnvelopeError> {
        let start = self.index;
        let root_kind = self.parse_value(2)?;
        let end = self.index;
        Ok(ToolInput {
            raw_json: self.input[start..end].into(),
            root_kind,
        })
    }

    fn parse_required_string(&mut self, maximum: usize) -> Result<String, EnvelopeError> {
        self.count_value()?;
        if self.peek_byte() != Some(b'"') {
            return Err(error(
                EnvelopeErrorCode::InvalidFieldType,
                "hook envelope field has an invalid JSON type",
            ));
        }
        let value = self.parse_string(maximum)?;
        if value.is_empty() {
            return Err(error(
                EnvelopeErrorCode::EmptyField,
                "hook envelope field must not be empty",
            ));
        }
        Ok(value)
    }

    fn parse_nullable_string(&mut self, maximum: usize) -> Result<Option<String>, EnvelopeError> {
        self.count_value()?;
        if self.consume_literal("null") {
            return Ok(None);
        }
        if self.peek_byte() != Some(b'"') {
            return Err(error(
                EnvelopeErrorCode::InvalidFieldType,
                "hook envelope field has an invalid JSON type",
            ));
        }
        let value = self.parse_string(maximum)?;
        if value.is_empty() {
            return Err(error(
                EnvelopeErrorCode::EmptyField,
                "hook envelope field must not be empty",
            ));
        }
        Ok(Some(value))
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonRootKind, EnvelopeError> {
        self.count_value()?;
        self.skip_whitespace();
        match self.peek_byte() {
            Some(b'{') => {
                self.parse_object(depth)?;
                Ok(JsonRootKind::Object)
            }
            Some(b'[') => {
                self.parse_array(depth)?;
                Ok(JsonRootKind::Array)
            }
            Some(b'"') => {
                self.parse_string(MAX_JSON_STRING_BYTES)?;
                Ok(JsonRootKind::String)
            }
            Some(b't') => {
                self.expect_literal("true")?;
                Ok(JsonRootKind::Boolean)
            }
            Some(b'f') => {
                self.expect_literal("false")?;
                Ok(JsonRootKind::Boolean)
            }
            Some(b'n') => {
                self.expect_literal("null")?;
                Ok(JsonRootKind::Null)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.parse_number()?;
                Ok(JsonRootKind::Number)
            }
            _ => Err(invalid_json()),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), EnvelopeError> {
        self.check_depth(depth)?;
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        if self.consume_byte(b'}') {
            return Ok(());
        }

        let mut keys = BTreeSet::new();
        loop {
            if keys.len() >= MAX_OBJECT_MEMBERS {
                return Err(error(
                    EnvelopeErrorCode::TooManyContainerEntries,
                    "JSON object exceeds the configured member limit",
                ));
            }
            let key = self.parse_string(MAX_JSON_STRING_BYTES)?;
            if !keys.insert(key) {
                return Err(error(
                    EnvelopeErrorCode::DuplicateField,
                    "JSON object contains a duplicate field",
                ));
            }
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            self.parse_value(depth + 1)?;
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                return Ok(());
            }
            self.expect_byte(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), EnvelopeError> {
        self.check_depth(depth)?;
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        if self.consume_byte(b']') {
            return Ok(());
        }

        let mut elements = 0_usize;
        loop {
            if elements >= MAX_ARRAY_ELEMENTS {
                return Err(error(
                    EnvelopeErrorCode::TooManyContainerEntries,
                    "JSON array exceeds the configured element limit",
                ));
            }
            self.parse_value(depth + 1)?;
            elements += 1;
            self.skip_whitespace();
            if self.consume_byte(b']') {
                return Ok(());
            }
            self.expect_byte(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_number(&mut self) -> Result<(), EnvelopeError> {
        self.consume_byte(b'-');
        match self.peek_byte() {
            Some(b'0') => {
                self.index += 1;
                if matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    return Err(invalid_json());
                }
            }
            Some(b'1'..=b'9') => {
                self.consume_digits();
            }
            _ => return Err(invalid_json()),
        }

        if self.consume_byte(b'.') {
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err(invalid_json());
            }
            self.consume_digits();
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            if !matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                return Err(invalid_json());
            }
            self.consume_digits();
        }
        Ok(())
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
    }

    fn parse_string(&mut self, maximum: usize) -> Result<String, EnvelopeError> {
        self.expect_byte(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self.peek_byte().ok_or_else(invalid_json)?;
            match byte {
                b'"' => {
                    self.index += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.index += 1;
                    self.parse_escape(&mut output)?;
                }
                0x00..=0x1f => return Err(invalid_json()),
                _ => {
                    let character = self.input[self.index..]
                        .chars()
                        .next()
                        .ok_or_else(invalid_json)?;
                    self.index += character.len_utf8();
                    output.push(character);
                }
            }
            if output.len() > maximum {
                return Err(error(
                    EnvelopeErrorCode::FieldTooLong,
                    "JSON string exceeds the configured byte limit",
                ));
            }
        }
    }

    fn parse_escape(&mut self, output: &mut String) -> Result<(), EnvelopeError> {
        let escape = self.peek_byte().ok_or_else(invalid_json)?;
        self.index += 1;
        match escape {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => self.parse_unicode_escape(output)?,
            _ => return Err(invalid_json()),
        }
        Ok(())
    }

    fn parse_unicode_escape(&mut self, output: &mut String) -> Result<(), EnvelopeError> {
        let first = self.parse_hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if !self.consume_literal("\\u") {
                return Err(invalid_json());
            }
            let second = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(invalid_json());
            }
            0x1_0000 + (((u32::from(first) - 0xd800) << 10) | (u32::from(second) - 0xdc00))
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(invalid_json());
        } else {
            u32::from(first)
        };
        let character = char::from_u32(scalar).ok_or_else(invalid_json)?;
        output.push(character);
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16, EnvelopeError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self
                .peek_byte()
                .and_then(hex_value)
                .ok_or_else(invalid_json)?;
            self.index += 1;
            value = (value << 4) | u16::from(digit);
        }
        Ok(value)
    }

    fn count_value(&mut self) -> Result<(), EnvelopeError> {
        self.values = self.values.saturating_add(1);
        if self.values > MAX_JSON_VALUES {
            return Err(error(
                EnvelopeErrorCode::TooManyJsonValues,
                "JSON value count exceeds the configured limit",
            ));
        }
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), EnvelopeError> {
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(error(
                EnvelopeErrorCode::NestingTooDeep,
                "JSON nesting exceeds the configured depth limit",
            ));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), EnvelopeError> {
        if self.consume_byte(expected) {
            Ok(())
        } else {
            Err(invalid_json())
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.peek_byte() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_literal(&mut self, expected: &str) -> Result<(), EnvelopeError> {
        if self.consume_literal(expected) {
            Ok(())
        } else {
            Err(invalid_json())
        }
    }

    fn consume_literal(&mut self, expected: &str) -> bool {
        if self.input[self.index..].starts_with(expected) {
            self.index += expected.len();
            true
        } else {
            false
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.index).copied()
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_json() -> EnvelopeError {
    error(
        EnvelopeErrorCode::InvalidJson,
        "hook envelope is not valid JSON",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterAssessment, AdapterError, EnvelopeAssessment, EnvelopeErrorCode, ExtractedToolInput,
        JsonRootKind, MAX_ENVELOPE_BYTES, MAX_JSON_NESTING_DEPTH, MAX_TOOL_COMMAND_BYTES,
        ToolInputAssessment, ToolInputErrorCode, assess_pre_tool_use,
        assess_supported_pre_tool_use, extract_tool_input, parse_pre_tool_use,
    };

    const VALID: &str = r#"{
        "session_id":"session-1",
        "transcript_path":null,
        "cwd":"F:\\Projects\\operation-firewall",
        "hook_event_name":"PreToolUse",
        "model":"gpt-5",
        "turn_id":"turn-1",
        "permission_mode":"default",
        "tool_name":"Bash",
        "tool_use_id":"tool-1",
        "tool_input":{"command":"git status","unicode":"\uD83D\uDD12"}
    }"#;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SecurityGate {
        Ready,
        Indeterminate,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExtractionGate {
        Extracted,
        Indeterminate,
    }

    #[test]
    fn valid_supported_envelope_becomes_a_typed_value() {
        let envelope = match parse_pre_tool_use(VALID.as_bytes()) {
            Ok(envelope) => envelope,
            Err(parse_error) => unreachable!("fixture must parse: {parse_error}"),
        };

        assert_eq!(envelope.session_id(), "session-1");
        assert_eq!(envelope.transcript_path(), None);
        assert_eq!(envelope.tool_name(), "Bash");
        assert_eq!(envelope.tool_input().root_kind(), JsonRootKind::Object);
        assert!(envelope.tool_input().byte_len() > 2);
    }

    #[test]
    fn unknown_duplicate_and_missing_fields_are_rejected() {
        let unknown = VALID.replacen(
            r#""session_id":"session-1","#,
            r#""session_id":"session-1","schema_version":"1.0","#,
            1,
        );
        assert_code(&unknown, EnvelopeErrorCode::UnknownField);

        let duplicate = VALID.replacen(
            r#""session_id":"session-1","#,
            r#""session_id":"session-1","session_id":"session-2","#,
            1,
        );
        assert_code(&duplicate, EnvelopeErrorCode::DuplicateField);

        let missing = VALID.replacen(r#""session_id":"session-1","#, "", 1);
        assert_code(&missing, EnvelopeErrorCode::MissingField);
    }

    #[test]
    fn protocol_tool_and_tool_input_shape_are_explicit() {
        let wrong_event = VALID.replace("PreToolUse", "PostToolUse");
        assert_code(&wrong_event, EnvelopeErrorCode::UnsupportedProtocol);

        let unsupported_tool = VALID.replace(r#""tool_name":"Bash""#, r#""tool_name":"WebSearch""#);
        assert_code(&unsupported_tool, EnvelopeErrorCode::UnsupportedTool);

        let scalar_input = VALID.replace(
            r#""tool_input":{"command":"git status","unicode":"\uD83D\uDD12"}"#,
            r#""tool_input":"git status""#,
        );
        assert_code(&scalar_input, EnvelopeErrorCode::InvalidFieldType);
    }

    #[test]
    fn size_depth_and_value_budgets_are_enforced() {
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            parse_pre_tool_use(&oversized),
            Err(parse_error) if parse_error.code() == EnvelopeErrorCode::InputTooLarge
        ));

        let nested = format!(
            "{{\"nested\":{}}}",
            "[".repeat(MAX_JSON_NESTING_DEPTH + 1) + &"]".repeat(MAX_JSON_NESTING_DEPTH + 1)
        );
        let deep = VALID.replace(
            r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
            &nested,
        );
        assert_code(&deep, EnvelopeErrorCode::NestingTooDeep);

        let many_values = format!(
            "{{\"values\":[{}]}}",
            std::iter::repeat_n("0", 4_096)
                .collect::<Vec<_>>()
                .join(",")
        );
        let excessive_values = VALID.replace(
            r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
            &many_values,
        );
        assert_code(&excessive_values, EnvelopeErrorCode::TooManyJsonValues);
    }

    #[test]
    fn malformed_unicode_numbers_and_nested_duplicates_are_rejected() {
        for invalid_input in [
            r#"{"command":"\uD800"}"#,
            r#"{"command":"\uDC00"}"#,
            r#"{"number":01}"#,
            r#"{"number":1.}"#,
            r#"{"command":"one","command":"two"}"#,
        ] {
            let malformed = VALID.replace(
                r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
                invalid_input,
            );
            assert!(parse_pre_tool_use(malformed.as_bytes()).is_err());
        }
    }

    #[test]
    fn every_truncated_recognized_envelope_is_indeterminate() {
        let bytes = VALID.as_bytes();
        for end in 0..bytes.len() {
            let Some(prefix) = bytes.get(..end) else {
                unreachable!("a prefix shorter than the whole must exist")
            };
            assert!(matches!(
                assess_pre_tool_use(prefix),
                EnvelopeAssessment::Indeterminate(_)
            ));
        }
    }

    #[test]
    fn red_first_witness_detects_fail_open_parser_fallback() {
        let malformed = VALID.replacen(r#""session_id":"session-1","#, "", 1);
        let invariant = |gate: fn(&[u8]) -> SecurityGate| {
            gate(malformed.as_bytes()) == SecurityGate::Indeterminate
        };

        assert!(!invariant(vulnerable_fail_open_gate));
        assert!(invariant(strict_gate));
    }

    #[test]
    fn bash_and_apply_patch_inputs_extract_into_distinct_types() {
        let bash = VALID.replace(
            r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
            r#"{"command":"printf '$HOME $(whoami) `id` ; && %PATH%'"}"#,
        );
        let bash_envelope = match parse_pre_tool_use(bash.as_bytes()) {
            Ok(envelope) => envelope,
            Err(parse_error) => unreachable!("Bash fixture must parse: {parse_error}"),
        };
        match extract_tool_input(&bash_envelope) {
            ToolInputAssessment::Extracted(ExtractedToolInput::Bash(input)) => {
                assert_eq!(input.command(), "printf '$HOME $(whoami) `id` ; && %PATH%'");
            }
            assessment => unreachable!("expected extracted Bash input, got {assessment:?}"),
        }

        let patch_text = "*** Begin Patch\n*** Add File: note.txt\n+literal $HOME\n*** End Patch";
        let apply_patch = VALID
            .replace(r#""tool_name":"Bash""#, r#""tool_name":"apply_patch""#)
            .replace(
                r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
                r#"{"command":"*** Begin Patch\n*** Add File: note.txt\n+literal $HOME\n*** End Patch"}"#,
            );
        let apply_patch_envelope = match parse_pre_tool_use(apply_patch.as_bytes()) {
            Ok(envelope) => envelope,
            Err(parse_error) => unreachable!("apply_patch fixture must parse: {parse_error}"),
        };
        match extract_tool_input(&apply_patch_envelope) {
            ToolInputAssessment::Extracted(ExtractedToolInput::ApplyPatch(input)) => {
                assert_eq!(input.patch(), patch_text);
            }
            assessment => {
                unreachable!("expected extracted apply_patch input, got {assessment:?}")
            }
        }
    }

    #[test]
    fn strict_payload_shape_failures_are_typed_indeterminate() {
        for (tool_input, expected) in [
            (r#"{}"#, ToolInputErrorCode::MissingField),
            (
                r#"{"description":"not authoritative"}"#,
                ToolInputErrorCode::UnknownField,
            ),
            (r#"{"command":null}"#, ToolInputErrorCode::InvalidFieldType),
            (
                r#"{"command":["git","status"]}"#,
                ToolInputErrorCode::InvalidFieldType,
            ),
            (r#"{"command":""}"#, ToolInputErrorCode::EmptyField),
            (r#"{"command":"\u2003\t"}"#, ToolInputErrorCode::EmptyField),
            (
                r#"{"command":"git status","description":"extra"}"#,
                ToolInputErrorCode::UnknownField,
            ),
        ] {
            let malformed = replace_tool_input(VALID, tool_input);
            assert!(matches!(
                assess_supported_pre_tool_use(malformed.as_bytes()),
                AdapterAssessment::Indeterminate(AdapterError::ToolInput(error))
                    if error.code() == expected
            ));
        }
    }

    #[test]
    fn duplicate_payload_fields_and_budget_failures_remain_indeterminate() {
        let duplicate = replace_tool_input(VALID, r#"{"command":"one","co\u006dmand":"two"}"#);
        assert!(matches!(
            assess_supported_pre_tool_use(duplicate.as_bytes()),
            AdapterAssessment::Indeterminate(AdapterError::Envelope(error))
                if error.code() == EnvelopeErrorCode::DuplicateField
        ));

        let maximum = replace_tool_input(
            VALID,
            &format!(r#"{{"command":"{}"}}"#, "x".repeat(MAX_TOOL_COMMAND_BYTES)),
        );
        assert!(matches!(
            assess_supported_pre_tool_use(maximum.as_bytes()),
            AdapterAssessment::Extracted(_)
        ));

        let oversized = replace_tool_input(
            VALID,
            &format!(
                r#"{{"command":"{}"}}"#,
                "x".repeat(MAX_TOOL_COMMAND_BYTES + 1)
            ),
        );
        assert!(matches!(
            assess_supported_pre_tool_use(oversized.as_bytes()),
            AdapterAssessment::Indeterminate(AdapterError::Envelope(error))
                if error.code() == EnvelopeErrorCode::FieldTooLong
        ));
    }

    #[test]
    fn every_truncated_extractable_tool_call_is_indeterminate() {
        let apply_patch = VALID
            .replace(r#""tool_name":"Bash""#, r#""tool_name":"apply_patch""#)
            .replace(
                r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
                r#"{"command":"*** Begin Patch\n*** Delete File: old.txt\n*** End Patch"}"#,
            );

        for fixture in [VALID, apply_patch.as_str()] {
            let bytes = fixture.as_bytes();
            for end in 0..bytes.len() {
                let Some(prefix) = bytes.get(..end) else {
                    unreachable!("a prefix shorter than the whole must exist")
                };
                assert!(matches!(
                    assess_supported_pre_tool_use(prefix),
                    AdapterAssessment::Indeterminate(_)
                ));
            }
        }
    }

    #[test]
    fn red_first_witness_rejects_envelope_only_operation_support() {
        let missing_command = replace_tool_input(VALID, r#"{}"#);
        let invariant = |gate: fn(&[u8]) -> ExtractionGate| {
            gate(missing_command.as_bytes()) == ExtractionGate::Indeterminate
        };

        assert!(!invariant(vulnerable_envelope_only_extraction_gate));
        assert!(invariant(strict_extraction_gate));
    }

    #[test]
    fn debug_and_errors_do_not_disclose_tool_payloads() {
        const CANARY: &str = "OFW_CANARY_SECRET_7f381a";
        let input = replace_tool_input(VALID, &format!(r#"{{"command":"{CANARY}"}}"#));
        let assessment = assess_supported_pre_tool_use(input.as_bytes());
        assert!(matches!(assessment, AdapterAssessment::Extracted(_)));
        assert!(!format!("{assessment:?}").contains(CANARY));

        let unknown = replace_tool_input(VALID, &format!(r#"{{"{CANARY}":"value"}}"#));
        let assessment = assess_supported_pre_tool_use(unknown.as_bytes());
        assert!(matches!(assessment, AdapterAssessment::Indeterminate(_)));
        assert!(!format!("{assessment:?}").contains(CANARY));
        assert!(!assessment.to_string().contains(CANARY));
    }

    fn strict_gate(input: &[u8]) -> SecurityGate {
        match assess_pre_tool_use(input) {
            EnvelopeAssessment::Parsed(_) => SecurityGate::Ready,
            EnvelopeAssessment::Indeterminate(_) => SecurityGate::Indeterminate,
        }
    }

    fn vulnerable_fail_open_gate(input: &[u8]) -> SecurityGate {
        match parse_pre_tool_use(input) {
            Ok(_) | Err(_) => SecurityGate::Ready,
        }
    }

    fn strict_extraction_gate(input: &[u8]) -> ExtractionGate {
        match assess_supported_pre_tool_use(input) {
            AdapterAssessment::Extracted(_) => ExtractionGate::Extracted,
            AdapterAssessment::Indeterminate(_) => ExtractionGate::Indeterminate,
        }
    }

    fn vulnerable_envelope_only_extraction_gate(input: &[u8]) -> ExtractionGate {
        match parse_pre_tool_use(input) {
            Ok(_) => ExtractionGate::Extracted,
            Err(_) => ExtractionGate::Indeterminate,
        }
    }

    fn replace_tool_input(fixture: &str, replacement: &str) -> String {
        fixture.replace(
            r#"{"command":"git status","unicode":"\uD83D\uDD12"}"#,
            replacement,
        )
    }

    fn assert_code(input: &str, expected: EnvelopeErrorCode) {
        assert!(matches!(
            parse_pre_tool_use(input.as_bytes()),
            Err(parse_error) if parse_error.code() == expected
        ));
    }
}
