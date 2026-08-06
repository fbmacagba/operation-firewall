//! Minimal bounded JSON writer.
//!
//! The enforcement runtime has no third-party crates. A serialization
//! dependency is planned for a later slice, but adding one requires the
//! recorded ownership, advisory, licence and transitive-surface review the
//! Milestone 1 design mandates before download. Emitting JSON is far smaller
//! than parsing it, so this writer keeps the runtime dependency-free until
//! that review actually happens.
//!
//! Every value is escaped, including values that are `&'static str` today.
//! An unescaped writer would be one refactor away from emitting a
//! payload-derived string unescaped, and Codex reads a malformed object as a
//! hook failure, which fails open.

/// Appends `value` to `output` as a quoted, escaped JSON string.
pub fn write_escaped(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            // RFC 8259 requires escaping every remaining control character.
            control if control < '\u{0020}' => {
                output.push_str("\\u");
                let code = control as u32;
                for shift in [12_u32, 8, 4, 0] {
                    let digit = (code >> shift) & 0xf;
                    // `digit` is masked to 0..=15, so the fallback is
                    // unreachable. Falling back rather than panicking keeps the
                    // object well formed: a truncated write is malformed, and
                    // Codex reads malformed as a hook failure, which fails open.
                    output.push(char::from_digit(digit, 16).unwrap_or('0'));
                }
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

/// A JSON object under construction.
pub struct Object {
    buffer: String,
    empty: bool,
}

impl Object {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: String::from("{"),
            empty: true,
        }
    }

    fn separate(&mut self) {
        if self.empty {
            self.empty = false;
        } else {
            self.buffer.push(',');
        }
    }

    pub fn string(&mut self, key: &str, value: &str) -> &mut Self {
        self.separate();
        write_escaped(key, &mut self.buffer);
        self.buffer.push(':');
        write_escaped(value, &mut self.buffer);
        self
    }

    pub fn boolean(&mut self, key: &str, value: bool) -> &mut Self {
        self.separate();
        write_escaped(key, &mut self.buffer);
        self.buffer.push(':');
        self.buffer.push_str(if value { "true" } else { "false" });
        self
    }

    pub fn integer(&mut self, key: &str, value: u64) -> &mut Self {
        self.separate();
        write_escaped(key, &mut self.buffer);
        self.buffer.push(':');
        self.buffer.push_str(&value.to_string());
        self
    }

    pub fn strings(&mut self, key: &str, values: &[&str]) -> &mut Self {
        self.separate();
        write_escaped(key, &mut self.buffer);
        self.buffer.push_str(":[");
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.buffer.push(',');
            }
            write_escaped(value, &mut self.buffer);
        }
        self.buffer.push(']');
        self
    }

    pub fn object(&mut self, key: &str, nested: Object) -> &mut Self {
        self.separate();
        write_escaped(key, &mut self.buffer);
        self.buffer.push(':');
        self.buffer.push_str(&nested.finish());
        self
    }

    #[must_use]
    pub fn finish(self) -> String {
        let mut buffer = self.buffer;
        buffer.push('}');
        buffer
    }
}

impl Default for Object {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Object, write_escaped};

    #[test]
    fn escaping_covers_quotes_backslashes_and_control_characters() {
        let mut output = String::new();
        write_escaped("a\"b\\c\nd\te\u{0001}f", &mut output);
        assert_eq!(output, "\"a\\\"b\\\\c\\nd\\te\\u0001f\"");
    }

    #[test]
    fn a_lone_control_character_uses_the_four_digit_form() {
        let mut output = String::new();
        write_escaped("\u{001f}", &mut output);
        assert_eq!(output, "\"\\u001f\"");
    }

    #[test]
    fn objects_nest_and_separate_correctly() {
        let mut inner = Object::new();
        inner.string("kind", "deny");
        let mut outer = Object::new();
        outer
            .string("schema_version", "1.0")
            .boolean("proof", false)
            .integer("count", 7)
            .strings("tools", &["Bash", "apply_patch"])
            .object("decision", inner);
        assert_eq!(
            outer.finish(),
            concat!(
                "{\"schema_version\":\"1.0\",\"proof\":false,\"count\":7,",
                "\"tools\":[\"Bash\",\"apply_patch\"],\"decision\":{\"kind\":\"deny\"}}"
            )
        );
    }

    #[test]
    fn an_empty_object_is_still_valid_json() {
        assert_eq!(Object::new().finish(), "{}");
    }
}
