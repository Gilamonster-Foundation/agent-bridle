use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `dirname` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("dirname".to_string(), dirname_main);
}

/// Placeholder implementation for the `dirname` command.
pub fn dirname_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `dirname` logic.
    0
}