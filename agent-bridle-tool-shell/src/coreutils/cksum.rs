use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `cksum` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("cksum".to_string(), cksum_main);
}

/// Placeholder implementation for the `cksum` command.
pub fn cksum_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `cksum` logic.
    0
}