//! Client side of the jail broker (#108): connect to the broker's Unix socket,
//! send a [`JailRequest`], receive a [`JailResponse`]. Unprivileged — this is the
//! API the leash calls to obtain a kernel-confined run without holding
//! `CAP_SYS_ADMIN` itself.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::protocol::{read_frame, write_frame, JailRequest, JailResponse};

/// Send `req` to the broker listening at `socket` and return its reply.
///
/// Transport/serialization failures surface as `Err`; a broker refusal is a
/// successful [`JailResponse::Rejected`] (the caller stays fail-closed either way).
pub fn request_jailed(socket: &Path, req: &JailRequest) -> io::Result<JailResponse> {
    let mut stream = UnixStream::connect(socket)?;
    let body = serde_json::to_vec(req).map_err(invalid)?;
    write_frame(&mut stream, &body)?;
    let reply = read_frame(&mut stream)?;
    serde_json::from_slice(&reply).map_err(invalid)
}

fn invalid(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
