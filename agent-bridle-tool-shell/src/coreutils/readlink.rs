use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `readlink` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("readlink".to_string(), readlink_main);
}

/// Placeholder implementation for the `readlink` command.
pub fn readlink_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `readlink` logic.
    0
}