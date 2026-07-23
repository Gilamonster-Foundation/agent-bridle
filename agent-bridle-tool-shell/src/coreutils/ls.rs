use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `ls` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("ls".to_string(), ls_main);
}

/// Placeholder implementation for the `ls` command.
pub fn ls_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `ls` logic.
    0
}