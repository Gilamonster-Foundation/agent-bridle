use std::collections::HashMap;
use std::ffi::OsString;

/// Register the `unexpand` command with the supplied registry.
pub fn register(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("unexpand".to_string(), unexpand_main);
}

/// Placeholder implementation for the `unexpand` command.
pub fn unexpand_main(args: Vec<OsString>) -> i32 {
    // TODO: implement real `unexpand` logic.
    0
}