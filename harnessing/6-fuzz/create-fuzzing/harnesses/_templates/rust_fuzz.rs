// cargo-fuzz harness template (language: rust).
//
// Install into the target clone via `cargo fuzz init` (creates
// fuzz/fuzz_targets/); dest is fuzz/fuzz_targets/<name>.rs. The harness
// entry in targets.json sets fuzz to the target name (file stem).
// Run via `make fuzz-<id>` or:
//   cargo +nightly fuzz run <name> -- -max_total_time=<secs>
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // let _ = target_crate::parse(s); // <- call the target function
        let _ = s;
    }
});
