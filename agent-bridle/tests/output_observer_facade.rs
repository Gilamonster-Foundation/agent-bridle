//! Public-facade presence check for the shell output observer contract.
#![cfg(any(feature = "shell", feature = "host-shell", feature = "brush"))]

use agent_bridle::{ShellInvocationId, ShellOutputObserver, ShellOutputStream};

struct Noop;

impl ShellOutputObserver for Noop {
    fn on_output(&self, _invocation: ShellInvocationId, _stream: ShellOutputStream, _chunk: &[u8]) {
    }
}

fn accepts_observer<T: ShellOutputObserver>(_observer: &T) {}

#[test]
fn shell_output_observer_types_are_publicly_reexported() {
    accepts_observer(&Noop);
    let stream = ShellOutputStream::Stdout;
    assert_eq!(stream, ShellOutputStream::Stdout);
}
