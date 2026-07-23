use std::collections::HashMap;
use std::ffi::OsString;

pub type BundledFn = fn(args: Vec<OsString>) -> i32;

pub fn register_commands(registry: &mut HashMap<String, BundledFn>) {
    registry.insert("ls".to_string(), ls_main);
}

fn ls_main(args: Vec<OsString>) -> i32 {
    // Placeholder implementation for `ls`.
    0
}
