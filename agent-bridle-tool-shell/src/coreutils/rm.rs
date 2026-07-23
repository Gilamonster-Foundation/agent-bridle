use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `rm` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("rm".to_string(), rm_main);
}

/// Placeholder implementation for the `rm` command.
pub fn rm_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `rm` logic.
    0
}