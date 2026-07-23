use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `tac` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("tac".to_string(), tac_main);
}

/// Placeholder implementation for the `tac` command.
pub fn tac_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `tac` logic.
    0
}