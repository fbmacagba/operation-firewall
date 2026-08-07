#![no_main]

//! The Codex envelope parser reads bytes an agent influenced, on the hot path
//! of a host that fails open. It must terminate and must not panic for any
//! input; a panic is an abnormal exit, and an abnormal exit is a hook failure.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The assertion is the absence of a panic and of a hang. The parser is
    // total by design -- every input maps to Extracted or Indeterminate.
    let _ = ofw_adapter_codex::assess_supported_pre_tool_use(data);
});
