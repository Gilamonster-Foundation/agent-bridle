"""Real-process tests: the inherited Strands helpers run through a real agent-bridle-mcp.

Skipped unless the server binary is found: ``$STRANDS_BRIDLE_MCP_BIN``, else
``target/debug/agent-bridle-mcp`` of the enclosing checkout.
"""

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from strands.sandbox.errors import SandboxPathNotFoundError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from strands_bridle import DENIED_EXIT_CODE, BridleSandbox  # noqa: E402

BINARY = os.environ.get("STRANDS_BRIDLE_MCP_BIN") or str(
    Path(__file__).resolve().parents[3] / "target" / "debug" / "agent-bridle-mcp"
)
pytestmark = [
    pytest.mark.skipif(
        not Path(BINARY).is_file(), reason=f"agent-bridle-mcp not built at {BINARY}"
    ),
    pytest.mark.skipif(
        sys.platform == "win32", reason="the carried Brush engine needs Linux or macOS"
    ),
]

#: What the inherited helpers run: base64, dirname, mkdir, rm, env, ls, plus an
#: interpreter. `cat` is for the test's own command. Nothing else is granted.
PROGRAMS = ["base64", "dirname", "mkdir", "rm", "env", "ls", "cat", "python3"]

#: A small capture cap, so a modest file overruns it.
CAP = 64 * 1024


def server_env(tmp_path, **overrides):
    grant = {
        "fs_read": "all",
        "fs_write": "all",
        "exec": {"only": PROGRAMS},
        "net": "all",
        "max_calls": "unlimited",
        "valid_for_generation": "all",
    }
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        # An empty HOME: the grant and config come only from this environment.
        "HOME": str(tmp_path / "home"),
        "AGENT_BRIDLE_CAVEATS": json.dumps(grant),
    }
    env.update(overrides)
    return env


@pytest.fixture
async def sandbox(tmp_path):
    async with BridleSandbox([BINARY], env=server_env(tmp_path)) as box:
        yield box


async def test_the_stock_helpers_read_write_list_run_and_remove(sandbox, tmp_path):
    target = tmp_path / "nested" / "note.txt"
    await sandbox.write_file(str(target), b"hello from strands\n")
    assert target.read_bytes() == b"hello from strands\n"
    assert await sandbox.read_file(str(target)) == b"hello from strands\n"

    names = [entry.name for entry in await sandbox.list_files(str(target.parent))]
    assert "note.txt" in names

    shown = await sandbox.execute(f"cat {target}")
    assert (shown.exit_code, shown.stdout) == (0, "hello from strands\n")
    assert sandbox.last_envelope["disclosure"]["engine"] == "brush"

    ran = await sandbox.execute_code("print(6 * 7)", "python3")
    assert (ran.exit_code, ran.stdout.strip()) == (0, "42")

    await sandbox.remove_file(str(target))
    assert not target.exists()
    with pytest.raises(SandboxPathNotFoundError):
        await sandbox.list_files(str(tmp_path / "absent"))


async def test_an_ungranted_program_is_refused_and_the_envelope_names_it(
    sandbox, tmp_path
):
    marker = tmp_path / "must-not-exist"
    # The path form reaches the exec check directly on Linux and macOS alike.
    result = await sandbox.execute(f"/usr/bin/touch {marker}")
    assert result.exit_code == DENIED_EXIT_CODE
    assert "agent-bridle:" in result.stderr
    assert not marker.exists()
    denials = sandbox.last_envelope["denials"]
    assert denials[0]["kind"] == "exec"
    assert "touch" in denials[0]["target"]


async def test_reading_a_file_past_the_capture_cap_raises(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(2 * CAP))
    env = server_env(tmp_path, BRIDLE_LIMITS_MAX_OUTPUT_BYTES=str(CAP))
    async with BridleSandbox([BINARY], env=env) as box:
        with pytest.raises(OSError, match="capture cap"):
            await box.read_file(str(big))


async def test_a_command_past_its_timeout_raises(sandbox):
    with pytest.raises(TimeoutError):
        await sandbox.execute("while :; do :; done", timeout=1)


async def test_a_256_kib_file_and_script_go_through(sandbox, tmp_path):
    payload = os.urandom(256 * 1024)
    target = tmp_path / "large.bin"
    await asyncio.wait_for(sandbox.write_file(str(target), payload), timeout=60)
    assert target.read_bytes() == payload

    code = "x = '" + "a" * (256 * 1024) + "'\nprint(len(x))"
    ran = await asyncio.wait_for(sandbox.execute_code(code, "python3"), timeout=60)
    assert (ran.exit_code, ran.stdout.strip()) == (0, str(256 * 1024))


async def test_a_write_past_the_request_cap_fails_fast(sandbox, tmp_path):
    target = tmp_path / "too-large.bin"
    with pytest.raises(OSError):
        await asyncio.wait_for(
            sandbox.write_file(str(target), os.urandom(1024 * 1024)), timeout=30
        )
    assert not target.exists() or target.stat().st_size == 0


def test_the_binary_under_test_is_the_one_named():
    assert shutil.which(BINARY) or Path(BINARY).is_file()
