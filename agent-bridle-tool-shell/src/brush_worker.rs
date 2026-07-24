//! Private, single-request protocol for the carried Brush worker.
//!
//! This entrypoint is reached only after [`agent_bridle_core::SandboxedWorker`]
//! has created a fresh process beneath the L3 boundary. It accepts one bounded
//! JSON request on stdin and emits one JSON response on stdout.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use agent_bridle_core::{
    AxisEnforcement, Caveats, Denial, Gate, Scope, Tool, ToolContext, ToolResult,
};
use serde::{Deserialize, Serialize};

use crate::brush_shell::run_in_brush;
use crate::caveat_interceptor::{CaveatInterceptor, DenialSink};
use crate::output_observer::OutputEmitter;

pub(crate) const WORKER_FLAG: &str = "--agent-bridle-worker";
pub(crate) const WORKER_KIND: &str = "brush";
const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkerRequest {
    version: u8,
    nonce: String,
    caveats: Caveats,
    strength_floor: AxisEnforcement,
    cmd: String,
    cwd: Option<String>,
    path: String,
    env: BTreeMap<String, String>,
    max_output: usize,
}

impl WorkerRequest {
    #[allow(
        clippy::too_many_arguments,
        reason = "the private protocol fields are deliberately explicit and immutable"
    )]
    pub(crate) fn new(
        nonce: String,
        caveats: Caveats,
        strength_floor: AxisEnforcement,
        cmd: String,
        cwd: Option<String>,
        path: String,
        env: BTreeMap<String, String>,
        max_output: usize,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            nonce,
            caveats,
            strength_floor,
            cmd,
            cwd,
            path,
            env,
            max_output,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkerResponse {
    pub(crate) exit_code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) denials: Vec<Denial>,
    pub(crate) error: Option<String>,
}

/// Serve exactly one Brush request and return the process exit status.
pub(crate) fn main() -> i32 {
    match serve_one() {
        Ok(response) => write_response(&response),
        Err(error) => write_response(&WorkerResponse {
            exit_code: 126,
            stdout: String::new(),
            stderr: String::new(),
            denials: Vec::new(),
            error: Some(error),
        }),
    }
}

fn serve_one() -> Result<WorkerResponse, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read worker request: {error}"))?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("worker request exceeds 1 MiB".to_string());
    }
    let request: WorkerRequest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid worker request: {error}"))?;
    if request.version != PROTOCOL_VERSION {
        return Err("unsupported worker protocol version".to_string());
    }
    let expected = std::env::var("AGENT_BRIDLE_WORKER_NONCE")
        .map_err(|_| "worker nonce is absent".to_string())?;
    if request.nonce != expected {
        return Err("worker nonce mismatch".to_string());
    }

    let generation = match &request.caveats.valid_for_generation {
        Scope::All => 0,
        Scope::Only(values) => values
            .iter()
            .copied()
            .next()
            .ok_or_else(|| "worker grant has no valid generation".to_string())?,
    };
    let tool = WorkerTool;
    let cx = Gate::new(generation)
        .with_strength_floor(request.strength_floor)
        .authorize(&tool, &request.caveats)
        .map_err(|error| format!("worker authorization failed: {error}"))?;
    run(request, cx)
}

fn run(request: WorkerRequest, cx: ToolContext) -> Result<WorkerResponse, String> {
    let sink: DenialSink = Arc::new(Mutex::new(Vec::new()));
    let cancel = Arc::new(AtomicBool::new(false));
    let interceptor =
        CaveatInterceptor::new(cx, Arc::clone(&sink)).with_cancel(Arc::clone(&cancel));
    let captured = run_in_brush(
        request.cmd,
        request.cwd,
        request.path,
        request.env,
        interceptor,
        request.max_output,
        OutputEmitter::default(),
    )
    .map_err(|error| error.to_string())?;
    let denials = sink
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok(WorkerResponse {
        exit_code: captured.exit_code,
        stdout: captured.stdout,
        stderr: captured.stderr,
        denials,
        error: None,
    })
}

fn write_response(response: &WorkerResponse) -> i32 {
    match serde_json::to_writer(std::io::stdout().lock(), response) {
        Ok(()) => {
            let _ = std::io::stdout().flush();
            0
        }
        Err(error) => {
            eprintln!("brush worker response failed: {error}");
            125
        }
    }
}

struct WorkerTool;

#[async_trait::async_trait]
impl Tool for WorkerTool {
    fn name(&self) -> &str {
        "brush-worker"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({})
    }

    async fn invoke(
        &self,
        _args: serde_json::Value,
        _cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        unreachable!("worker tool is used only to mint its context")
    }
}
