"""BridleSandbox: a Strands sandbox that runs everything under one agent-bridle grant.

A stock Strands harness runs shell commands, file tools and code through its
``Sandbox``. ``BridleSandbox`` implements the one primitive
``PosixShellSandbox`` needs, ``execute_streaming``, as a JSON-RPC client of one
``agent-bridle-mcp`` subprocess per sandbox. Every command the harness issues,
including the inherited file and code helpers, is then dispatched through the
bridle's ``shell`` tool against the grant that server was started with.

The grant is sourced by ``agent-bridle-mcp`` as always: ``$AGENT_BRIDLE_CAVEATS``
(JSON), else ``~/.agent-bridle/config.toml``. Nothing here decides authority.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
from collections.abc import AsyncGenerator
from typing import Any

from strands.sandbox import ExecutionResult, PosixShellSandbox, StreamChunk
from strands.sandbox.errors import SandboxTimeoutError
from strands.sandbox.posix_shell import validate_env_keys

#: The exit code reported for a command the leash refused.
DENIED_EXIT_CODE = 126


class BridleSandbox(PosixShellSandbox):
    """A sandbox backed by one ``agent-bridle-mcp`` subprocess.

    Args:
        command: The server's argv. Defaults to ``$STRANDS_BRIDLE_MCP_BIN``,
            else ``agent-bridle-mcp`` on ``PATH``.
        env: The server's environment (where its grant comes from). ``None``
            inherits this process's.
        cwd: The default working directory for commands.

    Attributes:
        last_envelope: The bridle result envelope of the most recent command,
            or ``None`` when the server returned an error with no envelope. A
            host reads the typed ``denials``, ``sandbox_kind`` and
            ``enforcement`` report from it.
    """

    def __init__(
        self,
        command: list[str] | None = None,
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        self._command = (
            list(command)
            if command
            else [os.environ.get("STRANDS_BRIDLE_MCP_BIN", "agent-bridle-mcp")]
        )
        self._env = env
        self._cwd = cwd
        self._proc: asyncio.subprocess.Process | None = None
        self._reader: asyncio.Task[None] | None = None
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._next_id = 0
        self.last_envelope: dict[str, Any] | None = None

    async def __aenter__(self) -> BridleSandbox:
        await self._start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def _start(self) -> None:
        if self._proc is not None:
            return
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            env=self._env,
            # One line of JSON holds a whole result; the default 64 KiB line
            # limit is far below the server's output cap.
            limit=64 * 1024 * 1024,
        )
        self._reader = asyncio.create_task(self._read_responses())
        await self._request("initialize", {})

    async def _read_responses(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        error: Exception = ConnectionError("agent-bridle-mcp closed its output")
        try:
            while line := await self._proc.stdout.readline():
                message = json.loads(line)
                waiter = self._pending.pop(message.get("id"), None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(message)
        except Exception as exc:  # a malformed line ends the session
            error = exc
        for waiter in self._pending.values():
            if not waiter.done():
                waiter.set_exception(error)
        self._pending.clear()

    async def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(message).encode() + b"\n")
        await self._proc.stdin.drain()

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        waiter: asyncio.Future[dict[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        self._pending[request_id] = waiter
        await self._send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        try:
            return await waiter
        except asyncio.CancelledError:
            # The task was cancelled: tell the server to drop the call. It
            # kills and reaps the worker; this side never sends a kill.
            self._pending.pop(request_id, None)
            await self._send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": request_id,
                        "reason": "the Strands task was cancelled",
                    },
                }
            )
            raise

    async def close(self) -> None:
        """Stop the server. Closing its input lets it answer what is in flight, then exit."""
        proc, self._proc = self._proc, None
        if proc is None:
            return
        if proc.stdin is not None:
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.terminate()  # the server drops its calls on SIGTERM
            await proc.wait()
        if self._reader is not None:
            await self._reader

    async def execute_streaming(
        self,
        command: str,
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[StreamChunk | ExecutionResult, None]:
        """Run ``command`` through the bridle's ``shell`` tool.

        Output arrives when the command ends, not as it is produced.

        Raises:
            SandboxTimeoutError: The command ran past ``timeout``.
            OSError: The output passed the server's capture cap, so the result
                is incomplete; or the server reported a protocol error.
            ValueError: ``env`` holds an invalid variable name.
        """
        arguments: dict[str, Any] = {"cmd": command}
        if cwd or self._cwd:
            arguments["cwd"] = cwd or self._cwd
        if env:
            validate_env_keys(env)
            arguments["env"] = dict(env)
        if timeout is not None:
            arguments["timeout_secs"] = max(1, math.ceil(timeout))

        await self._start()
        response = await self._request(
            "tools/call", {"name": "shell", "arguments": arguments}
        )
        if "error" in response:
            raise OSError(
                f"agent-bridle-mcp: {response['error'].get('message', 'protocol error')}"
            )
        result = response["result"]
        texts = [block.get("text", "") for block in result.get("content", [])]
        envelope = _envelope(texts)
        self.last_envelope = envelope

        if envelope is None:
            # A refusal with no envelope: the call was denied before it ran
            # (budget, an unknown tool, a pre-dispatch denial).
            reason = texts[0] if texts else "the tool call failed"
            yield ExecutionResult(DENIED_EXIT_CODE, "", f"agent-bridle: {reason}\n")
            return

        stdout = envelope.get("stdout") or ""
        stderr = envelope.get("stderr") or ""
        if envelope.get("timed_out"):
            raise SandboxTimeoutError(timeout, stdout, stderr)
        if envelope.get("stdout_truncated") or envelope.get("stderr_truncated"):
            raise OSError(
                "agent-bridle: output passed the capture cap; the result is incomplete"
            )

        exit_code = envelope.get("exit_code")
        if result.get("isError"):
            # The leash refused something. The reason leads the content; what
            # ran before the refusal is still in stdout.
            stderr = f"{stderr}agent-bridle: {texts[0]}\n"
            if not exit_code:
                exit_code = DENIED_EXIT_CODE
        if stdout:
            yield StreamChunk(stdout)
        if stderr:
            yield StreamChunk(stderr, "stderr")
        yield ExecutionResult(-1 if exit_code is None else exit_code, stdout, stderr)


def _envelope(texts: list[str]) -> dict[str, Any] | None:
    """The result envelope: the last text block, when it is one."""
    if not texts:
        return None
    try:
        parsed = json.loads(texts[-1])
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) and "sandbox_kind" in parsed else None
