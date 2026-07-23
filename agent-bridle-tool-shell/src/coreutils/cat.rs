use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `cat` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("cat".to_string(), cat_main);
}

/// Placeholder implementation for the `cat` command.
pub fn cat_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `cat` logic.
    0
}