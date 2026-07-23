use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `ln` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("ln".to_string(), ln_main);
}

/// Placeholder implementation for the `ln` command.
pub fn ln_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `ln` logic.
    0
}