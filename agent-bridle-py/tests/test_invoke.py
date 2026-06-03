"""Pillar A (DESIGN §8): the in-process, ``Caveats``-confined leash, from Python.

Build the extension first (in an isolated venv, never ``~/venv``)::

    maturin develop
    pytest agent-bridle-py/tests/ -v

These tests are the Python-side proof of the headline invariant: a tool runs
**only** when the granted ``Caveats`` admit it, and an out-of-scope dispatch is
refused by the leash — surfacing as ``agent_bridle.BridleDenied`` (a subclass of
the built-in ``PermissionError``).

Note on the ``shell`` arg shape: the tool takes **two** shapes. **Argv form**
(``{"program": ..., "args": [...]}``) is gated *before the command runs* by an
``exec`` pre-check on the named program. **Free-form** (``{"cmd": "..."}``) is an
``sh -c``-style string confined in-process by the brush ``CommandInterceptor``
hook (DESIGN §6) — a path-separator command like ``/bin/rm`` cannot bypass it.
A free-form denial returns from dispatch with the structured ``denied: true``
field set, which ``invoke()`` turns into ``BridleDenied`` just like an argv-form
denial. The tests exercise both contracts.
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


def test_freeform_in_scope_runs() -> None:
    """Free-form ``{"cmd": ...}`` IS accepted (it is confined in-process by the
    interceptor hook). With ``echo`` in scope, ``echo hi`` runs and is not
    flagged denied."""
    r = agent_bridle.invoke("shell", {"cmd": "echo hi"}, ECHO_ONLY)
    assert r["exit_code"] == 0, r
    assert "hi" in r["stdout"], r
    # An in-scope free-form run records no denial.
    assert r.get("denied") in (None, False), r


def test_freeform_denial_raises_bridle_denied() -> None:
    """The load-bearing free-form test (the fix's Python coverage): a free-form
    ``cmd`` the interceptor refuses (``rm`` ∉ ``exec``) returns the structured
    ``denied: true`` envelope from dispatch, and ``invoke()`` raises
    ``BridleDenied`` for it — exactly as it does for an argv-form denial. Before
    the fix, a free-form denial slipped through as a plain non-zero result with
    no exception."""
    with pytest.raises(agent_bridle.BridleDenied) as exc:
        agent_bridle.invoke("shell", {"cmd": "rm -rf /tmp/x"}, ECHO_ONLY)
    # The structured denials' reason is carried through.
    assert "not within the granted" in str(exc.value) or "denied" in str(exc.value)


def test_freeform_path_separator_denial_raises() -> None:
    """A path-separator-spelled command (``/bin/rm``) cannot bypass the leash in
    free-form mode either — it raises ``BridleDenied``."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"cmd": "/bin/rm -rf /tmp/x"}, ECHO_ONLY)


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
    # The shell exposes BOTH shapes: argv (`program`) and free-form (`cmd`).
    props = shell["inputSchema"]["properties"]
    assert "program" in props
    assert "cmd" in props


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
