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
``exec`` pre-check on the named program. **Free-form** (``{"cmd": "..."}``) is a
**safe-subset** string parsed by agent-bridle itself (ADR 0005): pipelines,
redirects, ``&&``/``||``/``;``, globbing, and allowlisted ``$VAR`` — with the
dynamic constructs refused by design. Every program is ``exec``-checked at the
spawn funnel before it runs, so a path-separator command like ``/bin/rm`` cannot
bypass it. A free-form denial returns from dispatch with the structured
``denied: true`` field set, which ``invoke()`` turns into ``BridleDenied`` just
like an argv-form denial. The tests exercise both contracts.
"""

from __future__ import annotations

import pytest

import agent_bridle

# A grant that authorizes executing *only* ``echo``. Since an omitted axis now
# defaults to bottom/deny (#271 / AB-009), the read and call-budget axes echo
# needs are named explicitly; fs_write and net stay omitted (denied).
# exec is restricted to echo (the invariant these tests exercise); the other
# axes are granted unrestricted so the host can actually run — a *restricted*
# fs/net axis it cannot enforce at the required strength floor would (correctly)
# refuse to run. Under the old omitted-defaults-to-top behavior these were
# implicit; deny-all-by-default (#271 / AB-009) makes them explicit.
ECHO_ONLY = {
    "exec": {"only": ["echo"]},
    "fs_read": "all",
    "fs_write": "all",
    "net": "all",
    "max_calls": "unlimited",
    "valid_for_generation": "all",
}


def test_consumer_contract_is_pinned() -> None:
    """#71: the published Pillar-A consumer contract, pinned in one place so a
    PyO3-layer regression is caught by CI: ``BridleDenied`` is a subclass of the
    built-in ``PermissionError`` (so ``except PermissionError`` catches a leash
    denial), and the ``shell`` tool is exposed by ``tool_names()``."""
    assert issubclass(agent_bridle.BridleDenied, PermissionError)
    assert "shell" in agent_bridle.tool_names()


def test_shell_is_registered() -> None:
    """The wheel is built with the ``shell`` feature, so the confined
    argv + safe-subset shell tool (ADR 0005) is present in the registry."""
    names = agent_bridle.tool_names()
    assert "shell" in names, f"shell missing from tool_names(): {names}"


def test_in_scope_echo_runs_and_captures_stdout() -> None:
    """An allowed dispatch passes the leash and runs: ``echo`` is within the
    granted ``exec`` scope, so it is spawned as an external program and stdout is
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


def test_exec_builtin_cannot_bypass_the_leash(tmp_path) -> None:
    """Security regression: a free-form ``exec`` cannot bypass the leash.

    The safe-subset engine (ADR 0005) has **no** ``exec`` builtin — ``exec`` is
    an ordinary, un-granted command name under the ``echo``-only grant — so
    ``exec /usr/bin/touch MARKER`` is denied at the spawn funnel: ``touch`` never
    runs (no marker), the host process is never replaced, and the free-form
    denial surfaces as ``BridleDenied``. (Historically a brush-era bug where the
    ``exec`` builtin called ``cmd.exec()`` directly and bypassed the funnel; the
    safe-subset engine has no such builtin.)
    """
    marker = tmp_path / "exec-bypass-marker"
    assert not marker.exists()
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke(
            "shell",
            {"cmd": f"exec /usr/bin/touch {marker}"},
            ECHO_ONLY,
        )
    assert not marker.exists(), "exec must not run the un-granted program"


def test_command_substitution_denial_does_not_panic(tmp_path) -> None:
    """Security regression: a ``$(...)`` command substitution is refused.

    The safe-subset engine (ADR 0005) **refuses dynamic constructs by design** —
    command substitution ``$(...)`` is rejected at parse time, before anything
    runs. ``invoke`` raises ``BridleDenied`` (structured ``denied: true``) and the
    victim file is untouched. (No interpreter ever evaluates the inner command.)
    """
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke(
            "shell",
            {"cmd": f"echo $(/bin/rm -rf {victim})"},
            ECHO_ONLY,
        )
    assert victim.exists(), "the denied rm must not have deleted the victim file"


def test_unknown_tool_raises_bridle_denied() -> None:
    """A registry miss surfaces uniformly as ``BridleDenied``."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("no_such_tool", {}, ECHO_ONLY)


def test_caveats_none_is_deny_all() -> None:
    """#271 / AB-009 regression: ``caveats=None`` authorizes NOTHING (deny-all).
    A missing leash is not a full leash. Before the fix this ran with full
    ambient authority (``Caveats::top()``); now an otherwise-valid command is
    refused because no axis is granted."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]})


def test_missing_axis_defaults_to_bottom() -> None:
    """#271 / AB-009 regression: an OMITTED axis defaults to bottom (deny), not
    top. ``exec`` grants echo but ``max_calls`` is omitted → ``AtMost(0)`` →
    budget-denied. Before the fix the omitted axis defaulted to top and echo
    ran."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke(
            "shell",
            {"program": "echo", "args": ["hi"]},
            {"exec": {"only": ["echo"]}},
        )


def test_explicit_all_axes_still_runs_unconfined() -> None:
    """The deliberate escape hatch: full ambient authority is available, but it
    must be ASKED for explicitly (every axis ``"all"``) rather than defaulted."""
    r = agent_bridle.invoke(
        "shell",
        {"program": "echo", "args": ["unconfined"]},
        {
            "exec": "all",
            "fs_read": "all",
            "fs_write": "all",
            "net": "all",
            "max_calls": "unlimited",
            "valid_for_generation": "all",
        },
    )
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
