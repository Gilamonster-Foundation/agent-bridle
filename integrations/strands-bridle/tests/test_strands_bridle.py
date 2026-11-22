"""Unit tests for BridleSandbox against a scripted JSON-RPC peer (no bridle binary)."""

import asyncio
import json
import sys
from pathlib import Path

import pytest
from strands.sandbox import ExecutionResult, StreamChunk
from strands.sandbox.errors import SandboxTimeoutError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from strands_bridle import DENIED_EXIT_CODE, BridleSandbox  # noqa: E402

FAKE_PEER = str(Path(__file__).resolve().parent / "fake_peer.py")


@pytest.fixture
async def peer(tmp_path):
    """A sandbox wired to the scripted peer, plus a reader for what it received."""
    log = tmp_path / "peer.log"
    sandbox = BridleSandbox([sys.executable, FAKE_PEER, str(log)])

    def received():
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    yield sandbox, received
    await sandbox.close()


async def test_a_command_yields_its_output_then_the_result(peer):
    sandbox, received = peer
    chunks = [chunk async for chunk in sandbox.execute_streaming("hello")]
    assert chunks == [
        StreamChunk("hello"),
        StreamChunk("warn", "stderr"),
        ExecutionResult(0, "hello", "warn"),
    ]
    assert sandbox.last_envelope["sandbox_kind"] == "none"
    assert [message["method"] for message in received()] == ["initialize", "tools/call"]


async def test_timeout_cwd_and_env_reach_the_shell_tool(peer):
    sandbox, _ = peer
    result = await sandbox.execute(
        "echo-arguments", timeout=1.2, cwd="/work", env={"A": "1"}
    )
    assert json.loads(result.stdout) == {
        "cmd": "echo-arguments",
        "cwd": "/work",
        "env": {"A": "1"},
        "timeout_secs": 2,
    }


async def test_an_invalid_env_name_is_refused_before_anything_is_sent(peer):
    sandbox, received = peer
    with pytest.raises(ValueError):
        await sandbox.execute("hello", env={"BAD NAME": "1"})
    assert received() == []


async def test_truncated_output_raises_instead_of_returning_a_short_result(peer):
    sandbox, _ = peer
    with pytest.raises(OSError, match="capture cap"):
        await sandbox.execute("truncated")


async def test_a_timed_out_command_raises_with_the_partial_output(peer):
    sandbox, _ = peer
    with pytest.raises(SandboxTimeoutError) as raised:
        await sandbox.execute("timeout", timeout=1)
    assert raised.value.stdout == "partial"
    assert raised.value.stderr == "timed out"


async def test_a_denied_command_fails_with_the_reason_and_keeps_what_ran(peer):
    sandbox, _ = peer
    result = await sandbox.execute("denied")
    assert result.exit_code == DENIED_EXIT_CODE
    assert result.stdout == "before\n"
    assert "agent-bridle: rm not granted" in result.stderr
    assert sandbox.last_envelope["denials"] == [
        {"kind": "exec", "target": "rm", "reason": "rm not granted"}
    ]


async def test_a_refusal_with_no_envelope_fails_with_the_reason(peer):
    sandbox, _ = peer
    result = await sandbox.execute("budget")
    assert result.exit_code == DENIED_EXIT_CODE
    assert "max_calls" in result.stderr
    assert sandbox.last_envelope is None


async def test_a_protocol_error_raises(peer):
    sandbox, _ = peer
    with pytest.raises(OSError, match="boom"):
        await sandbox.execute("protocol-error")


async def test_cancelling_the_task_tells_the_server_and_the_sandbox_keeps_working(peer):
    sandbox, received = peer
    task = asyncio.create_task(sandbox.execute("hang"))
    # Wait until the peer has the call, so the cancel is for a call in flight.
    for _ in range(200):
        if any(m.get("method") == "tools/call" for m in received()):
            break
        await asyncio.sleep(0.01)
    hang_id = next(m["id"] for m in received() if m.get("method") == "tools/call")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    result = await sandbox.execute("still-here")
    assert result.stdout == "still-here"
    cancels = [m for m in received() if m.get("method") == "notifications/cancelled"]
    assert [m["params"]["requestId"] for m in cancels] == [hang_id]
    assert all(
        "id" not in m for m in cancels
    ), "a cancel is a notification, never a request"
