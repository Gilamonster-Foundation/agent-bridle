//! Kernel-authenticated private control channels for Brush worker transitions.
//!
//! A fresh challenge binds every frame, but the challenge is not treated as
//! authentication. On Linux the authority frame must carry `SCM_CREDENTIALS`
//! from the worker's real parent. On macOS a pre/post snapshot of
//! `LOCAL_PEERPID` + the full `LOCAL_PEERTOKEN` + the live process image must
//! remain stable across the challenge exchange. Both paths also require the
//! peer image to be this exact executable. Other targets fail closed.

#[cfg(feature = "carried-coreutils")]
use std::ffi::{OsStr, OsString};
#[cfg(feature = "carried-coreutils")]
use std::io::BufReader;
use std::io::{Read, Write};
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(feature = "carried-coreutils")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;

use agent_bridle_core::{
    decode_trusted_worker_frame_header, decode_trusted_worker_request, encode_trusted_worker_hello,
    trusted_worker_frame_digest, TrustedWorkerRequest, TRUSTED_WORKER_ACK,
    TRUSTED_WORKER_BOOTSTRAP, TRUSTED_WORKER_FRAME_HEADER_LEN,
};
#[cfg(feature = "carried-coreutils")]
use agent_bridle_core::{encode_trusted_worker_frame_header, TRUSTED_WORKER_HELLO_LEN};
use serde::de::DeserializeOwned;

#[cfg(feature = "carried-coreutils")]
const CARRIED_ACK: [u8; 8] = *b"ABCU-A1\0";
#[cfg(feature = "carried-coreutils")]
const CARRIED_IDENTITY_DOMAIN: &[u8] = b"agent-bridle/carried-coreutil/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageIdentity {
    #[cfg(target_os = "linux")]
    dev: u64,
    #[cfg(target_os = "linux")]
    ino: u64,
    #[cfg(target_os = "macos")]
    path: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParentSnapshot {
    ppid: i32,
    peer_pid: i32,
    image: ImageIdentityState,
    #[cfg(target_os = "macos")]
    token: nix::sys::socket::audit_token_t,
}

#[derive(Debug, Clone, Copy)]
struct FrameCredentials {
    #[cfg(target_os = "linux")]
    pid: i32,
    #[cfg(target_os = "linux")]
    uid: u32,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ImageIdentityState {
    Known(ImageIdentity),
    Unknown,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn same_image(left: &ImageIdentityState, right: &ImageIdentityState) -> bool {
    match (left, right) {
        (ImageIdentityState::Known(a), ImageIdentityState::Known(b)) => a == b,
        _ => true,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn inspect_image_with_fallback(pid: i32) -> Result<ImageIdentityState, String> {
    match process_image(pid) {
        Ok(image) => Ok(ImageIdentityState::Known(image)),
        Err(error) if error.raw_os_error() == Some(13) => Ok(ImageIdentityState::Unknown),
        Err(error) => Err(format!("inspect process {pid} image: {error}")),
    }
}

/// Receive and authenticate the one core-framed Brush worker request on fd 0.
pub(crate) fn receive_worker_request<P: DeserializeOwned>(
) -> Result<TrustedWorkerRequest<P>, String> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return Err(
            "authenticated private worker control is unavailable on this platform".to_string(),
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let stdin = std::io::stdin();
        let owned = stdin
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| format!("duplicate worker control socket: {error}"))?;
        let mut stream = UnixStream::from(owned);

        let mut challenge = [0_u8; 32];
        getrandom::getrandom(&mut challenge)
            .map_err(|error| format!("create worker control challenge: {error}"))?;

        // This diagnostic copy is intentionally emitted before authentication.
        // It lets the regression exercise an interactive read/response attacker;
        // no authority is accepted until the kernel channel checks below pass.
        eprintln!(
            "agent-bridle-private-control-v1 challenge {}",
            hex(&challenge)
        );
        prepare_receiver(&stream)?;
        receive_bootstrap(&mut stream, "worker")?;
        let pre = parent_snapshot(&stream);
        stream
            .write_all(&encode_trusted_worker_hello(std::process::id(), challenge))
            .and_then(|()| stream.flush())
            .map_err(|error| format!("write worker control hello: {error}"))?;

        let mut header = [0_u8; TRUSTED_WORKER_FRAME_HEADER_LEN];
        let credentials = recv_exact_frame(&stream, &mut header)?;
        let post = parent_snapshot(&stream);
        verify_parent(pre, post, credentials)?;

        let (body_len, echoed_challenge, expected_digest) =
            decode_trusted_worker_frame_header(&header)?;
        if echoed_challenge != challenge {
            return Err("worker control challenge mismatch".to_string());
        }
        let mut body = vec![0_u8; body_len];
        stream
            .read_exact(&mut body)
            .map_err(|error| format!("read worker authority body: {error}"))?;
        if trusted_worker_frame_digest(&challenge, &body) != expected_digest {
            return Err("worker authority frame digest mismatch".to_string());
        }
        let request = decode_trusted_worker_request(&body)?;
        stream
            .write_all(&TRUSTED_WORKER_ACK)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("acknowledge worker authority frame: {error}"))?;
        retire_worker_stdin()?;
        Ok(request)
    }
}

/// Encode the exact carried utility identity (`name` + raw argv bytes).
#[cfg(feature = "carried-coreutils")]
pub(crate) fn carried_identity(name: &OsStr, args: &[OsString]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CARRIED_IDENTITY_DOMAIN);
    push_os(&mut bytes, name);
    bytes.extend_from_slice(&(args.len() as u64).to_le_bytes());
    for arg in args {
        push_os(&mut bytes, arg);
    }
    bytes
}

/// Prepare a parent endpoint before spawning a carried utility.
#[cfg(feature = "carried-coreutils")]
pub(crate) fn prepare_carried_parent(stream: &UnixStream) -> Result<(), String> {
    prepare_receiver(stream)
}

/// Parent half of carried-utility authentication.
///
/// Returns a buffered reader positioned immediately after the binary ACK; all
/// subsequent bytes are the utility's ordinary stderr.
#[cfg(feature = "carried-coreutils")]
pub(crate) fn authorize_carried_child(
    mut stream: UnixStream,
    child_pid: u32,
    expected_identity: &[u8],
) -> Result<BufReader<UnixStream>, String> {
    stream
        .write_all(&TRUSTED_WORKER_BOOTSTRAP)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("write carried control bootstrap: {error}"))?;

    // Linux authenticates the actual sender of each frame, so it can also
    // capture an image snapshot immediately before the hello. On macOS,
    // LOCAL_PEERPID/LOCAL_PEERTOKEN identify the most recent peer writer; the
    // child must write its hello before that snapshot can name the re-execed
    // child rather than the socketpair's creating parent.
    #[cfg(target_os = "linux")]
    let pre = child_snapshot(&stream, child_pid);
    let mut hello = [0_u8; TRUSTED_WORKER_HELLO_LEN];
    let hello_credentials = recv_exact_frame(&stream, &mut hello)?;
    let after_hello = child_snapshot(&stream, child_pid);
    #[cfg(target_os = "linux")]
    verify_child(pre, after_hello.clone(), hello_credentials, child_pid)?;
    #[cfg(target_os = "macos")]
    verify_child(
        after_hello.clone(),
        after_hello.clone(),
        hello_credentials,
        child_pid,
    )?;

    let (reported_pid, challenge) = agent_bridle_core::decode_trusted_worker_hello(&hello)?;
    if reported_pid != child_pid {
        return Err(format!(
            "carried child hello PID mismatch: spawned {child_pid}, reported {reported_pid}"
        ));
    }
    let digest = trusted_worker_frame_digest(&challenge, expected_identity);
    let header = encode_trusted_worker_frame_header(challenge, digest, expected_identity.len())?;
    stream
        .write_all(&header)
        .and_then(|()| stream.write_all(expected_identity))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("write carried authorization: {error}"))?;
    let mut ack = [0_u8; CARRIED_ACK.len()];
    let ack_credentials = recv_exact_frame(&stream, &mut ack)?;
    let after_ack = child_snapshot(&stream, child_pid);
    verify_child(after_hello, after_ack, ack_credentials, child_pid)?;
    if ack != CARRIED_ACK {
        return Err("carried child returned an invalid authentication ACK".to_string());
    }
    // Keep the child alive through the final image check. EOF alone cannot
    // release dispatch: a refused parent also closes its socket on error.
    stream
        .write_all(&CARRIED_ACK)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("confirm carried authentication: {error}"))?;
    // A confirmed fast utility may already have exited. Only the courtesy
    // half-close can tolerate that; every authentication check above must pass.
    if let Err(error) = stream.shutdown(std::net::Shutdown::Write) {
        if error.kind() != std::io::ErrorKind::NotConnected {
            return Err(format!("close carried authorization direction: {error}"));
        }
    }
    Ok(BufReader::new(stream))
}

/// Child half of carried-utility authentication on its duplex fd 2.
#[cfg(feature = "carried-coreutils")]
pub(crate) fn authenticate_carried_dispatch(name: &OsStr, args: &[OsString]) -> Result<(), String> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (name, args);
        return Err("authenticated carried dispatch is unavailable on this platform".to_string());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let stderr = std::io::stderr();
        let owned = stderr
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| format!("duplicate carried control socket: {error}"))?;
        let mut stream = UnixStream::from(owned);
        prepare_receiver(&stream)?;
        receive_bootstrap(&mut stream, "carried")?;
        let mut challenge = [0_u8; 32];
        getrandom::getrandom(&mut challenge)
            .map_err(|error| format!("create carried control challenge: {error}"))?;
        let pre = parent_snapshot(&stream)?;
        stream
            .write_all(&encode_trusted_worker_hello(std::process::id(), challenge))
            .and_then(|()| stream.flush())
            .map_err(|error| format!("write carried control hello: {error}"))?;

        let mut header = [0_u8; TRUSTED_WORKER_FRAME_HEADER_LEN];
        let credentials = recv_exact_frame(&stream, &mut header)?;
        let post = parent_snapshot(&stream)?;
        verify_parent(Ok(pre), Ok(post), credentials)?;

        let (body_len, echoed_challenge, expected_digest) =
            decode_trusted_worker_frame_header(&header)?;
        if echoed_challenge != challenge {
            return Err("carried control challenge mismatch".to_string());
        }
        let mut body = vec![0_u8; body_len];
        stream
            .read_exact(&mut body)
            .map_err(|error| format!("read carried identity body: {error}"))?;
        let actual_identity = carried_identity(name, args);
        if body != actual_identity
            || trusted_worker_frame_digest(&challenge, &body) != expected_digest
        {
            return Err("carried authorization does not match the exact utility argv".to_string());
        }

        stream
            .write_all(&CARRIED_ACK)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("write carried authentication ACK: {error}"))?;
        let mut confirmation = [0_u8; CARRIED_ACK.len()];
        stream
            .read_exact(&mut confirmation)
            .map_err(|error| format!("read carried authentication confirmation: {error}"))?;
        if confirmation != CARRIED_ACK {
            return Err("carried parent returned an invalid authentication confirmation".into());
        }
        set_cloexec(&stderr)?;
        Ok(())
    }
}

#[cfg(feature = "carried-coreutils")]
fn push_os(bytes: &mut Vec<u8>, value: &OsStr) {
    let value = value.as_bytes();
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Receive the fixed non-authority prelude with ordinary stream I/O.
///
/// The parent may queue this bootstrap immediately after spawning, before the
/// child enables Linux `SO_PASSCRED`. Requiring credentials on that already
/// queued prelude creates a startup race without authenticating any authority.
/// Every authority-bearing frame follows the child's hello and is still read
/// through `recv_exact_frame`, where credentials are mandatory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn receive_bootstrap(stream: &mut UnixStream, channel: &str) -> Result<(), String> {
    let mut bootstrap = [0_u8; TRUSTED_WORKER_BOOTSTRAP.len()];
    stream
        .read_exact(&mut bootstrap)
        .map_err(|error| format!("read {channel} control bootstrap: {error}"))?;
    if bootstrap != TRUSTED_WORKER_BOOTSTRAP {
        return Err(format!("{channel} control bootstrap mismatch"));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_receiver(stream: &UnixStream) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    nix::sys::socket::setsockopt(stream, nix::sys::socket::sockopt::PassCred, &true)
        .map_err(|error| format!("enable control-frame credentials: {error}"))?;
    #[cfg(target_os = "macos")]
    let _ = stream;
    Ok(())
}

#[cfg(target_os = "linux")]
fn recv_exact_frame(stream: &UnixStream, bytes: &mut [u8]) -> Result<FrameCredentials, String> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, UnixCredentials};
    use std::io::IoSliceMut;

    let expected_len = bytes.len();
    let (received_len, credentials) = {
        let mut iov = [IoSliceMut::new(bytes)];
        let mut cmsgspace = nix::cmsg_space!(UnixCredentials);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsgspace),
            MsgFlags::MSG_WAITALL,
        )
        .map_err(|error| format!("receive authenticated control frame: {error}"))?;
        let mut credentials = None;
        for control in message
            .cmsgs()
            .map_err(|error| format!("decode control-frame credentials: {error}"))?
        {
            if let ControlMessageOwned::ScmCredentials(seen) = control {
                if credentials.replace(seen).is_some() {
                    return Err("control frame carried duplicate credentials".to_string());
                }
            }
        }
        (message.bytes, credentials)
    };
    if received_len != expected_len {
        return Err(format!(
            "authenticated control frame was truncated ({} of {} bytes)",
            received_len, expected_len
        ));
    }
    let credentials =
        credentials.ok_or_else(|| "control frame carried no SCM_CREDENTIALS".to_string())?;
    Ok(FrameCredentials {
        pid: credentials.pid(),
        uid: credentials.uid(),
    })
}

#[cfg(target_os = "macos")]
fn recv_exact_frame(stream: &UnixStream, bytes: &mut [u8]) -> Result<FrameCredentials, String> {
    (&*stream)
        .read_exact(bytes)
        .map_err(|error| format!("receive authenticated control frame: {error}"))?;
    Ok(FrameCredentials {})
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parent_snapshot(stream: &UnixStream) -> Result<ParentSnapshot, String> {
    let ppid = nix::unistd::getppid().as_raw();
    #[cfg(target_os = "linux")]
    let peer_pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|error| format!("read worker-control peer credentials: {error}"))?
        .pid();
    #[cfg(target_os = "macos")]
    let peer_pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
        .map_err(|error| format!("read worker-control peer PID: {error}"))?;
    let image = inspect_image_with_fallback(peer_pid)?;
    Ok(ParentSnapshot {
        ppid,
        peer_pid,
        image,
        #[cfg(target_os = "macos")]
        token: nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerToken)
            .map_err(|error| format!("read worker-control peer audit token: {error}"))?,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_parent(
    pre: Result<ParentSnapshot, String>,
    post: Result<ParentSnapshot, String>,
    frame: FrameCredentials,
) -> Result<(), String> {
    let pre = pre?;
    let post = post?;
    if pre.ppid != post.ppid
        || pre.peer_pid != post.peer_pid
        || !same_image(&pre.image, &post.image)
    {
        return Err("worker-control peer identity changed during authentication".to_string());
    }
    if pre.peer_pid != pre.ppid {
        return Err(format!(
            "worker-control peer PID {} is not parent PID {}",
            pre.peer_pid, pre.ppid
        ));
    }
    if let ImageIdentityState::Known(peer_image) = pre.image {
        if current_image()? != peer_image {
            return Err("worker-control parent image is not this executable".to_string());
        }
    }
    #[cfg(target_os = "linux")]
    {
        if frame.pid != pre.peer_pid || frame.uid != nix::unistd::getuid().as_raw() {
            return Err("worker authority frame sender credentials do not match its parent".into());
        }
    }
    #[cfg(target_os = "macos")]
    let _ = frame;
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg(feature = "carried-coreutils")]
fn child_snapshot(_stream: &UnixStream, child_pid: u32) -> Result<ParentSnapshot, String> {
    let child_pid = i32::try_from(child_pid).map_err(|_| "child PID does not fit i32")?;
    let image = inspect_image_with_fallback(child_pid)?;
    Ok(ParentSnapshot {
        ppid: std::process::id() as i32,
        peer_pid: child_pid,
        image,
    })
}

#[cfg(target_os = "macos")]
#[cfg(feature = "carried-coreutils")]
fn child_snapshot(stream: &UnixStream, _child_pid: u32) -> Result<ParentSnapshot, String> {
    let peer_pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
        .map_err(|error| format!("read carried-child peer PID: {error}"))?;
    let image = inspect_image_with_fallback(peer_pid)?;
    Ok(ParentSnapshot {
        ppid: std::process::id() as i32,
        peer_pid,
        image,
        token: nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerToken)
            .map_err(|error| format!("read carried-child peer audit token: {error}"))?,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(feature = "carried-coreutils")]
fn verify_child(
    pre: Result<ParentSnapshot, String>,
    post: Result<ParentSnapshot, String>,
    frame: FrameCredentials,
    child_pid: u32,
) -> Result<(), String> {
    let pre = pre?;
    let post = post?;
    let child_pid = i32::try_from(child_pid).map_err(|_| "child PID does not fit i32")?;
    if pre.peer_pid != post.peer_pid
        || pre.peer_pid != child_pid
        || pre.ppid != post.ppid
        || !same_image(&pre.image, &post.image)
    {
        return Err("carried-child identity changed during authentication".to_string());
    }
    if let ImageIdentityState::Known(peer_image) = pre.image {
        if current_image()? != peer_image {
            return Err("carried-child image is not this executable".to_string());
        }
    }
    #[cfg(target_os = "linux")]
    {
        if frame.pid != child_pid || frame.uid != nix::unistd::getuid().as_raw() {
            return Err("carried-child frame credentials do not match the spawned child".into());
        }
    }
    #[cfg(target_os = "macos")]
    let _ = frame;
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_image(pid: i32) -> Result<ImageIdentity, std::io::Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(format!("/proc/{pid}/exe"))?;
    Ok(ImageIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

#[cfg(target_os = "macos")]
fn process_image(pid: i32) -> Result<ImageIdentity, std::io::Error> {
    let path = libproc::libproc::proc_pid::pidpath(pid).map_err(std::io::Error::other)?;
    let path = std::fs::canonicalize(path).map_err(std::io::Error::other)?;
    Ok(ImageIdentity { path })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_image() -> Result<ImageIdentity, String> {
    let pid = i32::try_from(std::process::id()).map_err(|_| "current PID does not fit i32")?;
    process_image(pid).map_err(|error| format!("inspect process {pid} image: {error}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn retire_worker_stdin() -> Result<(), String> {
    let null = std::fs::File::open("/dev/null")
        .map_err(|error| format!("open null stdin after worker authentication: {error}"))?;
    nix::unistd::dup2_stdin(&null)
        .map_err(|error| format!("retire worker control descriptor: {error}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(feature = "carried-coreutils")]
fn set_cloexec(fd: &impl AsFd) -> Result<(), String> {
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .map(drop)
    .map_err(|error| format!("mark private control descriptor close-on-exec: {error}"))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    #[cfg(any(target_os = "linux", feature = "carried-coreutils"))]
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn queued_bootstrap_precedes_credentialed_authority_frame_without_racing() {
        let (mut sender, mut receiver) = UnixStream::pair().expect("private socketpair");

        // Model the fast parent: the non-authority bootstrap is already queued
        // before the child has enabled credential reception.
        sender
            .write_all(&TRUSTED_WORKER_BOOTSTRAP)
            .expect("queue bootstrap");
        prepare_receiver(&receiver).expect("prepare authenticated receiver");
        receive_bootstrap(&mut receiver, "test").expect("receive queued bootstrap");

        // Authority is sent only after receiver preparation and must still
        // carry the sender's kernel credentials.
        let authority = *b"AUTH-V1\0";
        sender
            .write_all(&authority)
            .expect("write authority-shaped frame");
        let mut received = [0_u8; 8];
        let credentials =
            recv_exact_frame(&receiver, &mut received).expect("receive credentialed frame");
        assert_eq!(received, authority);
        assert_eq!(credentials.pid, std::process::id() as i32);
        assert_eq!(credentials.uid, nix::unistd::getuid().as_raw());
    }

    #[cfg(feature = "carried-coreutils")]
    mod carried_confirmation {
        use super::*;
        use std::os::fd::OwnedFd;
        use std::process::{Child, Command, ExitStatus, Stdio};
        use std::time::{Duration, Instant};

        const MARKER_ENV: &str = "AB_TEST_CARRIED_CONFIRMATION_MARKER";
        const BOUND: Duration = Duration::from_secs(5);

        struct ReapChild(Child);

        impl Drop for ReapChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        impl ReapChild {
            fn wait(&mut self) -> ExitStatus {
                let deadline = Instant::now() + BOUND;
                loop {
                    if let Some(status) = self.0.try_wait().expect("poll owned child") {
                        return status;
                    }
                    assert!(Instant::now() < deadline, "carried child exceeded deadline");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }

        /// Same-image real child grounds the carried handshake's requirement
        /// that dispatch follow the parent's final identity verification.
        #[test]
        #[ignore = "private child fixture, launched by the confirmation tests"]
        fn child() {
            let marker = std::env::var_os(MARKER_ENV).expect("private marker path");
            let code = match authenticate_carried_dispatch(OsStr::new("echo"), &[]) {
                Ok(()) => {
                    std::fs::write(marker, b"DISPATCHED").expect("write dispatch marker");
                    0
                }
                Err(_) => 64,
            };
            std::process::exit(code);
        }

        fn check_confirmation(label: &str, confirmation: Option<&[u8]>, succeeds: bool) {
            let dir = std::env::temp_dir().join(format!(
                "ab-carried-confirmation-{}-{label}",
                std::process::id()
            ));
            std::fs::create_dir(&dir).expect("create unique fixture directory");
            let marker = dir.join("dispatched");
            let (mut parent, child) = UnixStream::pair().expect("private socketpair");
            parent.set_read_timeout(Some(BOUND)).unwrap();
            parent.set_write_timeout(Some(BOUND)).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--ignored",
                    "--exact",
                    "private_control::tests::carried_confirmation::child",
                    "--nocapture",
                ])
                .env_clear()
                .env(MARKER_ENV, &marker)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(OwnedFd::from(child)));
            let mut child = ReapChild(command.spawn().expect("spawn same-image child"));
            drop(command);

            parent.write_all(&TRUSTED_WORKER_BOOTSTRAP).unwrap();
            let mut hello = [0; TRUSTED_WORKER_HELLO_LEN];
            parent.read_exact(&mut hello).expect("read child hello");
            let (pid, challenge) = agent_bridle_core::decode_trusted_worker_hello(&hello).unwrap();
            assert_eq!(pid, child.0.id());
            let identity = carried_identity(OsStr::new("echo"), &[]);
            let header = encode_trusted_worker_frame_header(
                challenge,
                trusted_worker_frame_digest(&challenge, &identity),
                identity.len(),
            )
            .unwrap();
            parent.write_all(&header).unwrap();
            parent.write_all(&identity).unwrap();
            let mut ack = [0; CARRIED_ACK.len()];
            parent.read_exact(&mut ack).expect("read authenticated ACK");
            assert_eq!(ack, CARRIED_ACK);
            if let Some(confirmation) = confirmation {
                parent
                    .write_all(confirmation)
                    .expect("send final confirmation");
            } else {
                parent.shutdown(std::net::Shutdown::Write).unwrap();
            }

            let status = child.wait();
            assert_eq!(status.code(), Some(if succeeds { 0 } else { 64 }));
            assert_eq!(marker.exists(), succeeds, "dispatch requires confirmation");
            if succeeds {
                assert_eq!(std::fs::read(&marker).unwrap(), b"DISPATCHED");
            }
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn eof_after_ack_does_not_release_carried_dispatch() {
            check_confirmation("eof", None, false);
        }

        #[test]
        fn invalid_confirmation_does_not_release_carried_dispatch() {
            check_confirmation("invalid", Some(b"INVALID!"), false);
        }

        #[test]
        fn verified_confirmation_releases_carried_dispatch() {
            check_confirmation("valid", Some(&CARRIED_ACK), true);
        }
    }
}
