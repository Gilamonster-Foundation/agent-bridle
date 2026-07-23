use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `nl` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("nl".to_string(), nl_main);
}

/// Placeholder implementation for the `nl` command.
pub fn nl_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `nl` logic.
    0
}