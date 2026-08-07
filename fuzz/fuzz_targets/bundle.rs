#![no_main]

//! Policy bundles are untrusted input read from a repository. Beyond not
//! panicking, the property that matters is that a parsed bundle never carries
//! a weakening -- and that is structural, since `Restriction` has no `Allow`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = ofw_policy::parse_bundle(data) {
        // Anything that parses must compose. A bundle that loads and then
        // cannot be used would strand an operator with a policy that is
        // neither active nor reported as broken.
        let _ = ofw_policy::EffectivePolicy::compose([bundle]);
    }
});
