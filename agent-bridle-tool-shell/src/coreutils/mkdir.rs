use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `mkdir` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("mkdir".to_string(), mkdir_main);
}

/// Placeholder implementation for the `mkdir` command.
pub fn mkdir_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `mkdir` logic.
    0
}