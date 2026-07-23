use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `wc` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("wc".to_string(), wc_main);
}

/// Placeholder implementation for the `wc` command.
pub fn wc_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `wc` logic.
    0
}