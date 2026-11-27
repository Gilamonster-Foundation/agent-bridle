//! Host-owned command preparation and scoped helper callbacks.
//!
//! These contracts describe trusted host callbacks, not a host command executor.
//! Implementations MUST enforce domain policy: authenticated helper messages are
//! still untrusted input. Transport and shell activation are separate; no callback
//! is invoked by the shell yet.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use agent_bridle_core::{ToolContext, ToolError, ToolResult};

/// Caller-filled native command data before any host-provided preparation.
///
/// The embedder MUST resolve the executable and absolute cwd and preserve exact
/// argument boundaries and the explicit exported environment when constructing it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrokerCommand {
    /// Resolved executable path; source spelling is kept separately.
    pub program: PathBuf,
    /// Original command spelling before executable resolution.
    pub original_command: OsString,
    /// Argument zero presented to the native program.
    pub argv0: OsString,
    /// Exact argument boundaries, excluding argv[0].
    pub args: Vec<OsString>,
    /// Explicit exported environment; the embedder MUST NOT inherit ambient
    /// environment entries.
    pub env: Vec<(OsString, OsString)>,
    /// Final absolute working directory.
    pub cwd: PathBuf,
}

/// Cancellation and lifetime bound shared with the owning worker invocation.
#[derive(Clone)]
pub struct BrokerControl {
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) deadline: Instant,
}

impl BrokerControl {
    /// Whether the owner has cancelled or the invocation deadline has elapsed.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }

    /// Refuse work after cancellation or timeout.
    pub fn check(&self) -> ToolResult<()> {
        if self.is_cancelled() {
            Err(ToolError::denied(
                "command broker invocation cancelled or budget exhausted",
            ))
        } else {
            Ok(())
        }
    }

    /// The invocation's fixed deadline; a callback cannot extend it.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// Caller-filled identity of a helper making a scoped callback.
///
/// The embedder MUST populate and verify these fields from kernel observations,
/// not request-body claims, before admitting a callback. This struct performs no
/// identity lookup or authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerPeer {
    /// Actual peer process ID, not a value asserted by the request body.
    pub process_id: u32,
    /// Opaque OS birth observation guarding PID reuse, never a caveat lifetime.
    pub process_birth: u64,
    /// Actual direct parent process ID.
    pub parent_process_id: u32,
    /// Canonical executable image of the helper.
    pub executable: PathBuf,
    /// Canonical executable image of its direct parent.
    pub parent_executable: PathBuf,
    /// OS process birth identity of the direct parent, guarding PID reuse.
    pub parent_birth: u64,
}

/// Caller-filled native process identity for spawn registration.
///
/// The embedder MUST capture and verify these fields from kernel observations
/// before admitting helper requests; this struct performs no identity lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerProcess {
    /// Actual native child process ID.
    pub process_id: u32,
    /// Canonical executable path.
    pub executable: PathBuf,
    /// OS birth identity captured before helper requests are admitted.
    pub birth: u64,
}

/// Invocation-local opaque helper policy and any resources it must retain.
///
/// The owner MUST retain this object until the native worker has been stopped
/// and reaped and all callbacks have joined. Implementations can own hook-directory
/// leases here. A helper's message kind or success claim is never authority:
/// implementations MUST validate canonical payloads and actual repository state
/// independently.
pub trait BrokerSession: Send + Sync {
    /// An implementation MUST bind the native child's actual PID before any
    /// helper request is admitted. On error, the embedder MUST abort the launch
    /// owner and prevent successful helper replies.
    fn on_spawn(&self, process: &BrokerProcess, control: &BrokerControl) -> ToolResult<()>;

    /// Handle opaque helper bytes. The embedder MUST authenticate the helper and
    /// enforce the 512 KiB request payload bound before calling this method.
    /// Replies have only the codec's 1 MiB encoded-frame bound, not a 512 KiB
    /// payload cap; the embedder MUST refuse replies exceeding that frame bound.
    fn request(
        &self,
        peer: &BrokerPeer,
        payload: &[u8],
        control: &BrokerControl,
    ) -> ToolResult<Vec<u8>>;
}

/// Host preparation for a selected native command.
///
/// The embedder MUST preserve program, cwd, argv[0], and stdio, and recheck the
/// resulting command and explicit descriptor delegation against the final
/// execution policy before spawn. It MUST retain the callback session through
/// owner cleanup. These obligations are not implemented by this data type.
pub struct PreparedBrokerCommand {
    /// Explicit trusted image reached by a platform launcher after exec.
    /// For `None`, the embedder MUST require the exact admitted executable image.
    /// It MUST obtain this policy from the trusted host, never from a helper's
    /// reported path or basename.
    pub expected_process_image: Option<PathBuf>,
    /// Replacement native argument vector, or `None` to retain exact arguments.
    pub args: Option<Vec<OsString>>,
    /// Environment updates for protected helpers; the embedder MUST retain
    /// other entries.
    pub env: Vec<(OsString, OsString)>,
    /// Explicit Unix descriptor number for the scoped helper endpoint.
    /// The embedder MUST require >=3 and refuse a collision with an existing
    /// shell redirection.
    pub target_fd: i32,
    /// Scoped host callback policy and resource lease.
    pub session: Arc<dyn BrokerSession>,
}

/// Host-owned optional preparation of already-resolved native commands.
///
/// On `None`, the embedder MUST leave normal execution unchanged. It MUST supply
/// the exact original invocation context; implementations MUST NOT replace or
/// widen it. This is not a host command-execution API.
pub trait CommandBroker: Send + Sync {
    /// Read-only fixed-worker alias directories the embedder MUST prepare before
    /// admission.
    ///
    /// The embedder MUST accept only flat symlink directories targeting the fixed
    /// worker image, without adding executable authority or widening the invocation
    /// context. Its fence integration MUST refuse any effective write scope that
    /// reaches these paths or their relocation ancestors; an all-files write grant
    /// cannot protect these resources. This trait performs none of those checks.
    fn read_only_resources(&self, _context: &ToolContext) -> ToolResult<Vec<PathBuf>> {
        Ok(Vec::new())
    }

    /// Prepare a command or leave it unchanged. An implementation MUST stay
    /// within the supplied context.
    fn prepare(
        &self,
        command: &BrokerCommand,
        context: &ToolContext,
        control: &BrokerControl,
    ) -> ToolResult<Option<PreparedBrokerCommand>>;
}
