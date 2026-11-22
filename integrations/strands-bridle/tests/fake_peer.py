"""A scripted JSON-RPC peer standing in for agent-bridle-mcp in unit tests.

Usage: fake_peer.py LOG. Every message received is appended to LOG as one JSON
line, so a test can see what the sandbox sent.
"""

import json
import sys


def envelope(**fields):
    base = {
        "sandbox_kind": "none",
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
    }
    base.update(fields)
    return base


def text(value):
    return {
        "type": "text",
        "text": value if isinstance(value, str) else json.dumps(value),
    }


def reply(request_id, result):
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n"
    )
    sys.stdout.flush()


def main():
    log = open(sys.argv[1], "a", encoding="utf-8")
    for line in sys.stdin:
        message = json.loads(line)
        log.write(json.dumps(message) + "\n")
        log.flush()
        method, request_id = message.get("method"), message.get("id")
        if method == "initialize":
            reply(request_id, {"protocolVersion": "2024-11-05"})
        elif method == "tools/call":
            arguments = message["params"]["arguments"]
            cmd = arguments["cmd"]
            if cmd == "hang":
                continue  # never answered: the test cancels it
            if cmd == "protocol-error":
                error = {"code": -32603, "message": "boom"}
                sys.stdout.write(
                    json.dumps({"jsonrpc": "2.0", "id": request_id, "error": error})
                    + "\n"
                )
                sys.stdout.flush()
            elif cmd == "truncated":
                reply(
                    request_id,
                    {
                        "content": [text(envelope(stdout="x", stdout_truncated=True))],
                        "isError": False,
                    },
                )
            elif cmd == "timeout":
                timed_out = envelope(
                    exit_code=124, stdout="partial", stderr="timed out", timed_out=True
                )
                reply(request_id, {"content": [text(timed_out)], "isError": False})
            elif cmd == "denied":
                denial = {"kind": "exec", "target": "rm", "reason": "rm not granted"}
                denied = envelope(stdout="before\n", denied=True, denials=[denial])
                reply(
                    request_id,
                    {
                        "content": [text("rm not granted"), text(denied)],
                        "isError": True,
                    },
                )
            elif cmd == "budget":
                reply(
                    request_id,
                    {
                        "content": [text("denied: call budget (max_calls) exhausted")],
                        "isError": True,
                    },
                )
            elif cmd == "echo-arguments":
                reply(
                    request_id,
                    {
                        "content": [
                            text(envelope(stdout=json.dumps(arguments, sort_keys=True)))
                        ],
                        "isError": False,
                    },
                )
            else:
                reply(
                    request_id,
                    {
                        "content": [text(envelope(stdout=cmd, stderr="warn"))],
                        "isError": False,
                    },
                )


if __name__ == "__main__":
    main()
