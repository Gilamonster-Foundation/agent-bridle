use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `expand` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("expand".to_string(), expand_main);
}

/// Placeholder implementation for the `expand` command.
pub fn expand_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `expand` logic.
    0
}