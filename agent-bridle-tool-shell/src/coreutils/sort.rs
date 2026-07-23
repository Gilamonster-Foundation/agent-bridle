use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `sort` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("sort".to_string(), sort_main);
}

/// Placeholder implementation for the `sort` command.
pub fn sort_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `sort` logic.
    0
}