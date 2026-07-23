use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `rmdir` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("rmdir".to_string(), rmdir_main);
}

/// Placeholder implementation for the `rmdir` command.
pub fn rmdir_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `rmdir` logic.
    0
}