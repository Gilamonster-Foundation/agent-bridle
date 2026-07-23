use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `realpath` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("realpath".to_string(), realpath_main);
}

/// Placeholder implementation for the `realpath` command.
pub fn realpath_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `realpath` logic.
    0
}