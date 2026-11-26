//! Private checked framing extracted from the vendored broker transport.
//! Content identity is the canonical MerkleNode CID, including causal parents.
//! This module performs no peer authentication, I/O setup, or host callbacks.

use agent_bridle_core::{ToolError, ToolResult};
use content_addressable::{canonical, ContentId, MerkleNode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Read, Write};

const MAX_FRAME: usize = 1024 * 1024;
const MAX_PAYLOAD: usize = MAX_FRAME / 2;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    version: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    error: Option<String>,
    endpoint: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frame {
    id: ContentId,
    node: MerkleNode<Body>,
}

pub(super) fn make_frame(
    payload: Vec<u8>,
    challenge: Vec<u8>,
    parents: BTreeSet<ContentId>,
    error: Option<String>,
    endpoint: bool,
) -> ToolResult<Frame> {
    let node = MerkleNode::new(
        Body {
            version: 1,
            challenge,
            payload,
            error,
            endpoint,
        },
        parents,
    );
    let id = node
        .id()
        .map_err(|error| ToolError::denied(error.to_string()))?;
    Ok(Frame { id, node })
}

pub(super) fn verify_frame(
    frame: &Frame,
    challenge: &[u8],
    parents: BTreeSet<ContentId>,
) -> ToolResult<()> {
    if challenge.len() != 32
        || frame
            .node
            .id()
            .map_err(|error| ToolError::denied(error.to_string()))?
            != frame.id
        || frame.node.payload().version != 1
        || frame.node.payload().challenge != challenge
        || frame.node.parents() != &parents
    {
        return Err(ToolError::denied(
            "broker frame identity, freshness, or causal link mismatch",
        ));
    }
    Ok(())
}

/// Keep the channel and syscall phase without erasing the I/O error kind.
pub(crate) fn broker_io(operation: &str, error: std::io::Error) -> ToolError {
    ToolError::Exec(std::io::Error::new(
        error.kind(),
        format!(
            "broker RPC socket {operation}: {error} (kind={:?}, raw_os_error={:?})",
            error.kind(),
            error.raw_os_error()
        ),
    ))
}

pub(super) fn write_frame(stream: &mut impl Write, frame: &Frame) -> ToolResult<()> {
    let bytes = canonical::to_canonical_dagcbor(frame)
        .map_err(|error| ToolError::denied(error.to_string()))?;
    if bytes.len() > MAX_FRAME {
        return Err(ToolError::denied("broker frame exceeds its bound"));
    }
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .map_err(|error| broker_io("write frame length", error))?;
    stream
        .write_all(&bytes)
        .map_err(|error| broker_io("write frame body", error))?;
    stream
        .flush()
        .map_err(|error| broker_io("flush frame", error))?;
    Ok(())
}

pub(super) fn read_frame(stream: &mut impl Read) -> ToolResult<Frame> {
    let mut length = [0; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| broker_io("read frame length", error))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(ToolError::denied(
            "broker frame length is outside its bound",
        ));
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| broker_io("read frame body", error))?;
    // Decoder errors can quote peer-supplied field names or values. This error
    // also reaches the server diagnostic stream, so retain only the phase.
    canonical::from_canonical_dagcbor_checked(&bytes)
        .map_err(|_| ToolError::denied("invalid canonical broker frame"))
}

/// The receiving path must check the request role before handing bytes to policy.
pub(super) fn read_request(stream: &mut impl Read, challenge: &[u8]) -> ToolResult<Frame> {
    let request = read_frame(stream)?;
    verify_frame(&request, challenge, BTreeSet::new())?;
    if request.node.payload().error.is_some() || request.node.payload().endpoint {
        return Err(ToolError::denied("invalid broker request role"));
    }
    if request.node.payload().payload.len() > MAX_PAYLOAD {
        return Err(ToolError::denied(
            "broker request exceeds its payload bound",
        ));
    }
    Ok(request)
}

#[cfg(test)]
mod tests;
