use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `cp` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("cp".to_string(), cp_main);
}

/// Placeholder implementation for the `cp` command.
pub fn cp_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `cp` logic.
    0
}