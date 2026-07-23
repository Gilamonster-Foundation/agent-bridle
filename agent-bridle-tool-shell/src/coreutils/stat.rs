use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `stat` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("stat".to_string(), stat_main);
}

/// Placeholder implementation for the `stat` command.
pub fn stat_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `stat` logic.
    0
}