use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `sha256sum` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("sha256sum".to_string(), sha256sum_main);
}

/// Placeholder implementation for the `sha256sum` command.
pub fn sha256sum_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `sha256sum` logic.
    0
}