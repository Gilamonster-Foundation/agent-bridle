use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `basename` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("basename".to_string(), basename_main);
}

/// Placeholder implementation for the `basename` command.
pub fn basename_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `basename` logic.
    0
}