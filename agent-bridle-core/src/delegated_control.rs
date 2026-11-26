//! Bounded transport for an explicitly delegated Unix control endpoint.
//!
//! This is a descriptor transport, not authentication or a grant. Callers must
//! authenticate the enclosing private channel before accepting an endpoint and
//! apply their own protocol policy to every request carried by it.

use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use rustix::io::{IoSlice, IoSliceMut};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use crate::{ToolError, ToolResult};

const MARKER: [u8; 8] = *b"ABTC-F1\0";

/// Send exactly one separate Unix stream endpoint over an authenticated channel.
///
/// Ownership stays with the caller; the receiver obtains a new owned reference.
/// No filesystem path is opened and no filesystem/network grant is changed.
pub fn send_control_endpoint(channel: &UnixStream, endpoint: &UnixStream) -> ToolResult<()> {
    let descriptors = [endpoint.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(ToolError::denied(
            "control endpoint ancillary buffer is too small",
        ));
    }
    let sent = rustix::net::sendmsg(
        channel,
        &[IoSlice::new(&MARKER)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    if sent == 0 || sent > MARKER.len() {
        return Err(ToolError::denied(
            "control endpoint transfer made no progress",
        ));
    }
    (&*channel).write_all(&MARKER[sent..])?;
    Ok(())
}

/// Receive exactly one connected Unix stream endpoint, owned and close-on-exec.
///
/// Only call this after authenticating the channel peer. Unknown markers,
/// truncated control data, missing/extra descriptors, non-sockets and other
/// socket families are rejected. Rejected descriptors are closed by ownership.
pub fn receive_control_endpoint(channel: &UnixStream) -> ToolResult<UnixStream> {
    let mut marker = [0; MARKER.len()];
    // Linux SO_PASSCRED may append credentials to the existing authenticated
    // bootstrap. Leave bounded room for them as well as an extra descriptor,
    // so duplicate descriptors are rejected explicitly rather than accepted.
    let mut space = [MaybeUninit::uninit(); 256];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = rustix::net::recvmsg(
        channel,
        &mut [IoSliceMut::new(&mut marker)],
        &mut ancillary,
        // Linux makes the received descriptors CLOEXEC atomically, avoiding a
        // concurrent fork/exec inheritance window. macOS has no equivalent;
        // its confined spawn funnel additionally scrubs all ambient fds.
        #[cfg(target_os = "linux")]
        RecvFlags::CMSG_CLOEXEC,
        #[cfg(not(target_os = "linux"))]
        RecvFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut descriptors = Vec::new();
    for item in ancillary.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(fds) => descriptors.extend(fds),
            #[cfg(target_os = "linux")]
            RecvAncillaryMessage::ScmCredentials(_) => {}
            _ => {
                return Err(ToolError::denied(
                    "unexpected control endpoint ancillary data",
                ))
            }
        }
    }
    if received.bytes == 0
        || received.bytes > marker.len()
        || received.flags.contains(ReturnFlags::CTRUNC)
        || received.flags.contains(ReturnFlags::TRUNC)
        || descriptors.len() != 1
    {
        return Err(ToolError::denied(
            "control transfer requires exactly one complete endpoint",
        ));
    }
    (&*channel).read_exact(&mut marker[received.bytes..])?;
    if marker != MARKER {
        return Err(ToolError::denied(
            "invalid control endpoint transfer marker",
        ));
    }
    let endpoint = descriptors.pop().expect("exactly one descriptor checked");
    rustix::io::fcntl_setfd(&endpoint, rustix::io::FdFlags::CLOEXEC)
        .map_err(std::io::Error::from)?;
    if rustix::net::sockopt::socket_type(&endpoint).map_err(std::io::Error::from)?
        != rustix::net::SocketType::STREAM
        || rustix::net::getsockname(&endpoint)
            .map_err(std::io::Error::from)?
            .address_family()
            != rustix::net::AddressFamily::UNIX
    {
        return Err(ToolError::denied(
            "delegated control endpoint must be a Unix stream socket",
        ));
    }
    let endpoint = UnixStream::from(endpoint);
    endpoint.peer_addr()?;
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_endpoint_is_usable_and_close_on_exec() {
        let (parent, child) = UnixStream::pair().unwrap();
        let (endpoint, mut peer) = UnixStream::pair().unwrap();
        send_control_endpoint(&parent, &endpoint).unwrap();
        let mut received = receive_control_endpoint(&child).unwrap();
        assert!(rustix::io::fcntl_getfd(&received)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        drop(endpoint);
        received.write_all(b"private").unwrap();
        let mut bytes = [0; 7];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"private");
        // The original bootstrap is an independent channel, not the broker.
        (&parent).write_all(b"a").unwrap();
        let mut byte = [0];
        (&child).read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
    }

    #[test]
    fn missing_or_duplicate_endpoints_are_refused() {
        let (parent, child) = UnixStream::pair().unwrap();
        (&parent).write_all(&MARKER).unwrap();
        assert!(receive_control_endpoint(&child).is_err());
        let (one, _peer) = UnixStream::pair().unwrap();
        let (two, _peer) = UnixStream::pair().unwrap();
        let descriptors = [one.as_fd(), two.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        rustix::net::sendmsg(
            &parent,
            &[IoSlice::new(&MARKER)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(receive_control_endpoint(&child).is_err());
    }

    #[test]
    fn ordinary_files_cannot_be_transferred_as_control_sockets() {
        let (parent, child) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let descriptors = [file.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        rustix::net::sendmsg(
            &parent,
            &[IoSlice::new(&MARKER)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(receive_control_endpoint(&child).is_err());
        assert!(file.metadata().is_ok());
    }

    fn send_raw(channel: &UnixStream, fds: &[std::os::fd::BorrowedFd<'_>], marker: &[u8]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(80))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(fds)));
        assert_eq!(
            rustix::net::sendmsg(
                channel,
                &[IoSlice::new(marker)],
                &mut ancillary,
                SendFlags::empty()
            )
            .unwrap(),
            marker.len()
        );
    }

    #[test]
    fn malformed_transfers_close_every_received_descriptor() {
        // 80 descriptors exceed the receiver's fixed ancillary buffer.
        for (marker, count) in [
            (b"wrong!!!".as_slice(), 1),
            (&MARKER[..3], 1),
            (&MARKER, 2),
            (&MARKER, 80),
        ] {
            let (parent, child) = UnixStream::pair().unwrap();
            let (endpoint, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            send_raw(&parent, &vec![endpoint.as_fd(); count], marker);
            parent.shutdown(std::net::Shutdown::Write).unwrap();
            drop(endpoint);
            assert!(receive_control_endpoint(&child).is_err());
            assert_eq!(
                peer.read(&mut [0]).unwrap(),
                0,
                "rejected descriptors leaked"
            );
        }
    }

    #[test]
    fn split_marker_is_completed_without_losing_the_endpoint() {
        let (parent, child) = UnixStream::pair().unwrap();
        let (endpoint, mut peer) = UnixStream::pair().unwrap();
        send_raw(&parent, &[endpoint.as_fd()], &MARKER[..3]);
        (&parent).write_all(&MARKER[3..]).unwrap();
        let mut received = receive_control_endpoint(&child).unwrap();
        received.write_all(b"x").unwrap();
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn wrong_socket_type_family_and_disconnected_stream_are_refused() {
        use rustix::net::{socket, AddressFamily, SocketType};
        for (family, kind) in [
            (AddressFamily::UNIX, SocketType::DGRAM),
            (AddressFamily::INET, SocketType::STREAM),
            (AddressFamily::UNIX, SocketType::STREAM),
        ] {
            let (parent, child) = UnixStream::pair().unwrap();
            let endpoint = socket(family, kind, None).unwrap();
            rustix::io::fcntl_setfd(&endpoint, rustix::io::FdFlags::CLOEXEC).unwrap();
            send_raw(&parent, &[endpoint.as_fd()], &MARKER);
            assert!(receive_control_endpoint(&child).is_err());
            assert!(
                rustix::io::fcntl_getfd(&endpoint).is_ok(),
                "sender retains ownership"
            );
        }
    }
}
