use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `split` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("split".to_string(), split_main);
}

/// Placeholder implementation for the `split` command.
pub fn split_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `split` logic.
    0
}