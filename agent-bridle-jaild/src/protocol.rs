//! Wire protocol for the jail broker (#108 / ADR 0013 D4).
//!
//! Length-prefixed JSON frames (`u32` little-endian length + JSON body) over a
//! Unix socket. The request carries the authority [`Caveats`] — **not** a
//! pre-built rootfs plan — so the privileged broker derives the jail itself and
//! never trusts a client-supplied filesystem layout.
//!
//! These types are pure data and compile everywhere; the transport lives in
//! [`crate::client`] / [`crate::broker`].

use std::io::{self, Read, Write};

use agent_bridle_core::Caveats;
use serde::{Deserialize, Serialize};

/// A client's request: run `program` (with `args`) in a jail derived from
/// `caveats`. `program` must be within the caveats' `exec` scope; the broker
/// resolves it to the granted on-host binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailRequest {
    /// The effective authority the client presents. The broker builds the minimal
    /// rootfs from this and enforces program identity against its `exec` scope.
    pub caveats: Caveats,
    /// The program to run — a bare name (`"cat"`) or a path; only its file name is
    /// matched against the `exec` scope.
    pub program: String,
    /// Arguments passed to the program (UTF-8).
    #[serde(default)]
    pub args: Vec<String>,
}

/// The broker's reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JailResponse {
    /// The program ran in the jail. `code` is `None` if it was killed by a signal.
    Ran {
        /// Exit code, or `None` if terminated by a signal.
        code: Option<i32>,
        /// Captured standard output.
        stdout: Vec<u8>,
        /// Captured standard error.
        stderr: Vec<u8>,
    },
    /// The request was refused (unconfined exec, un-granted program, plan/jail
    /// failure). The leash stays fail-closed: a `Rejected` is never a silent run.
    Rejected {
        /// Human-readable reason.
        reason: String,
    },
}

/// The largest frame the broker will read — a DoS backstop against a client
/// announcing an enormous length (64 MiB; requests/responses are tiny).
pub const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// Write one length-prefixed frame.
pub fn write_frame<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(bytes)?;
    w.flush()
}

/// Read one length-prefixed frame (rejecting an oversized announced length).
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::Scope;

    #[test]
    fn frame_round_trip() {
        let mut wire: Vec<u8> = Vec::new();
        write_frame(&mut wire, b"hello jail").unwrap();
        let mut cursor = std::io::Cursor::new(wire);
        let got = read_frame(&mut cursor).unwrap();
        assert_eq!(got, b"hello jail");
    }

    #[test]
    fn read_frame_rejects_oversized_length() {
        // A frame announcing > MAX_FRAME must be refused before allocating.
        let mut wire = (MAX_FRAME + 1).to_le_bytes().to_vec();
        wire.extend_from_slice(b"....");
        let err = read_frame(&mut std::io::Cursor::new(wire)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn request_and_response_serde_round_trip() {
        let req = JailRequest {
            caveats: Caveats {
                exec: Scope::only(["cat".to_string()]),
                ..Caveats::top()
            },
            program: "cat".to_string(),
            args: vec!["/work/hello".to_string()],
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: JailRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.program, "cat");
        assert_eq!(back.args, vec!["/work/hello".to_string()]);

        for resp in [
            JailResponse::Ran {
                code: Some(0),
                stdout: b"hi\n".to_vec(),
                stderr: Vec::new(),
            },
            JailResponse::Rejected {
                reason: "nope".to_string(),
            },
        ] {
            let b = serde_json::to_vec(&resp).unwrap();
            let r: JailResponse = serde_json::from_slice(&b).unwrap();
            match (resp, r) {
                (JailResponse::Ran { code: a, .. }, JailResponse::Ran { code: b, .. }) => {
                    assert_eq!(a, b)
                }
                (JailResponse::Rejected { reason: a }, JailResponse::Rejected { reason: b }) => {
                    assert_eq!(a, b)
                }
                _ => panic!("variant mismatch after round-trip"),
            }
        }
    }
}
