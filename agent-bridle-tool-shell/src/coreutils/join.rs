use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `join` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("join".to_string(), join_main);
}

/// Placeholder implementation for the `join` command.
pub fn join_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `join` logic.
    0
}