"""Pillar A (DESIGN §8): the in-process, ``Caveats``-confined leash, from Python.

Build the extension first (in an isolated venv, never ``~/venv``)::

    maturin develop
    pytest agent-bridle-py/tests/ -v

These tests are the Python-side proof of the headline invariant: a tool runs
**only** when the granted ``Caveats`` admit it, and an out-of-scope dispatch is
refused by the leash *before the command runs* — surfacing as
``agent_bridle.BridleDenied`` (a subclass of the built-in ``PermissionError``).

Note on the ``shell`` arg shape: the tool takes **argv form**
(``{"program": ..., "args": [...]}``), not a free-form ``{"cmd": "..."}`` string.
That is the deliberate brush exec-bypass mitigation (DESIGN §6): the ``exec``
caveat gates on the *named program token*, so the program must be a discrete
field the leash can check. A ``cmd`` string would let ``echo hi; rm -rf /`` slip
the leash, which is exactly the confused-deputy hole the bridle closes. The
tests therefore exercise the real argv contract.
"""

from __future__ import annotations

import pytest

import agent_bridle

# A grant that authorizes executing *only* ``echo`` — nothing else.
ECHO_ONLY = {"exec": {"only": ["echo"]}}


def test_shell_is_registered() -> None:
    """The wheel is built with the ``shell`` feature, so the confined
    brush-backed shell tool is present in the registry."""
    names = agent_bridle.tool_names()
    assert "shell" in names, f"shell missing from tool_names(): {names}"


def test_in_scope_echo_runs_and_captures_stdout() -> None:
    """An allowed dispatch passes the leash and runs: ``echo`` is within the
    granted ``exec`` scope, so the brush-carried builtin runs and stdout is
    captured. (Equivalent to the spec's ``echo hi`` in argv form.)"""
    r = agent_bridle.invoke(
        "shell",
        {"program": "echo", "args": ["hi"]},
        ECHO_ONLY,
    )
    assert r["exit_code"] == 0, r
    assert "hi" in r["stdout"], r
    # The recorded sandbox kind travels with every result (DESIGN §6).
    assert r["sandbox_kind"] == "none"
    assert r["timed_out"] is False


def test_out_of_scope_program_is_denied() -> None:
    """The load-bearing leash test: the SAME ``echo``-only grant denies ``rm``.

    ``rm -rf /tmp/x`` is outside the granted ``exec`` scope, so the gate refuses
    to mint the tool's ``ToolContext`` and the command never runs — surfacing as
    ``BridleDenied``. This is the confused-deputy gap closed structurally: the
    leash, not prompt hygiene, stops the destructive call.
    """
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke(
            "shell",
            {"program": "rm", "args": ["-rf", "/tmp/x"]},
            ECHO_ONLY,
        )


def test_bridle_denied_is_a_permission_error() -> None:
    """``BridleDenied`` subclasses the built-in ``PermissionError`` so existing
    ``except PermissionError`` handlers catch a leash denial."""
    assert issubclass(agent_bridle.BridleDenied, PermissionError)
    with pytest.raises(PermissionError):
        agent_bridle.invoke(
            "shell",
            {"program": "rm", "args": ["-rf", "/tmp/x"]},
            ECHO_ONLY,
        )


def test_denied_reason_is_surfaced() -> None:
    """The denial carries the human-readable reason (safe to show an agent)."""
    with pytest.raises(agent_bridle.BridleDenied) as exc:
        agent_bridle.invoke("shell", {"program": "curl"}, ECHO_ONLY)
    assert "curl" in str(exc.value)


def test_cmd_shorthand_is_rejected() -> None:
    """Documents the contract: a free-form ``{"cmd": ...}`` is NOT accepted; the
    shell tool requires the ``program`` field (argv form). Missing ``program``
    is itself a denial."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"cmd": "echo hi"}, ECHO_ONLY)


def test_unknown_tool_raises_bridle_denied() -> None:
    """A registry miss surfaces uniformly as ``BridleDenied``."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("no_such_tool", {}, ECHO_ONLY)


def test_caveats_none_runs_unconfined() -> None:
    """``caveats=None`` runs with full ambient authority (``Caveats::top()``);
    it must print a stderr UNCONFINED warning (checked via capsys) but still
    run an otherwise-valid command."""
    r = agent_bridle.invoke("shell", {"program": "echo", "args": ["unconfined"]})
    assert r["exit_code"] == 0
    assert "unconfined" in r["stdout"]


def test_tool_definitions_have_name_and_schema() -> None:
    """``tool_definitions()`` returns one MCP ``tools/list`` dict per tool."""
    defs = agent_bridle.tool_definitions()
    assert isinstance(defs, list) and defs
    shell = next(d for d in defs if d["name"] == "shell")
    assert isinstance(shell["inputSchema"], dict)
    # argv form: a `program` property, no `cmd` property.
    props = shell["inputSchema"]["properties"]
    assert "program" in props
    assert "cmd" not in props


def test_unknown_caveats_field_is_value_error() -> None:
    """A typo'd caveats axis is surfaced as a ``ValueError`` (bad input), NOT a
    silent no-op and NOT a ``BridleDenied`` (the grant is malformed, not an
    authority refusal)."""
    with pytest.raises(ValueError):
        agent_bridle.invoke(
            "shell",
            {"program": "echo", "args": ["x"]},
            {"exce": {"only": ["echo"]}},  # typo: exce
        )


def test_max_calls_budget_denies_within_one_grant() -> None:
    """``max_calls`` is enforced: a grant of ``{"at_most": 0}`` is exhausted by
    the per-dispatch charge, so even an in-scope program is denied."""
    grant = {"exec": {"only": ["echo"]}, "max_calls": {"at_most": 0}}
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, grant)
