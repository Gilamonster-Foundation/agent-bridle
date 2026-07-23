use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `mv` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("mv".to_string(), mv_main);
}

/// Placeholder implementation for the `mv` command.
pub fn mv_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `mv` logic.
    0
}