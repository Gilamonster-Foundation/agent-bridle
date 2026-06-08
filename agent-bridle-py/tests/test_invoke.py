"""Pillar A (DESIGN §8): the in-process, ``Caveats``-confined leash, from Python.

Build the extension first (in an isolated venv, never ``~/venv``)::

    maturin develop
    pytest agent-bridle-py/tests/ -v

These tests exercise the leash mechanics through the Python wheel: dispatch
flows through the registry's gate, a registry miss / malformed grant / exhausted
budget all surface as the right exception, and the ``shell`` tool advertises its
stable input schema.

Note on the ``shell`` tool: it is currently the **fail-closed STUB**. The
brush-backed confined shell (which gated commands in-process via a
``CommandInterceptor`` exec/open hook) depended on a *git* fork of brush, which
crates.io forbids, so it was removed to unblock publishing (see the workspace
CHANGELOG). The wheel's ``invoke()`` builds the default registry, whose ``shell``
tool **denies every invocation and spawns nothing**, raising
``agent_bridle.BridleDenied``. To actually run commands today, a host uses the
Rust ``registry_with_shell`` escalation seam (`--insecure` /
``--dangerously-allow-all`` on ``agent-bridle-mcp``); that opt-in is not exposed
through this Pillar-A wheel. When the brush hook is upstreamed, the confined
shell returns and the run-and-capture tests below come back with it.
"""

from __future__ import annotations

import pytest

import agent_bridle

# A grant that authorizes executing *only* ``echo`` — nothing else. Kept to show
# that the stub denies regardless of how generous (or narrow) the grant is.
ECHO_ONLY = {"exec": {"only": ["echo"]}}


def test_shell_is_registered() -> None:
    """The wheel is built with the ``shell`` feature, so the ``shell`` tool
    (currently the fail-closed stub) is present in the registry."""
    names = agent_bridle.tool_names()
    assert "shell" in names, f"shell missing from tool_names(): {names}"


def test_shell_stub_denies_in_scope_program() -> None:
    """The stub denies even an in-scope ``echo`` (it runs nothing): the
    brush-backed confined shell is pending upstream, so the published default is
    fail-closed. Surfaces as ``BridleDenied``."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, ECHO_ONLY)


def test_shell_stub_denies_freeform() -> None:
    """Free-form ``{"cmd": ...}`` is denied by the stub too — nothing spawns."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"cmd": "echo hi"}, ECHO_ONLY)


def test_shell_stub_denial_hints_at_escalation() -> None:
    """The stub's denial reason points the operator at the escalation flags so
    the deny-only default is discoverable, not mysterious."""
    with pytest.raises(agent_bridle.BridleDenied) as exc:
        agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, ECHO_ONLY)
    msg = str(exc.value)
    assert "--insecure" in msg or "--dangerously-allow-all" in msg, msg


def test_bridle_denied_is_a_permission_error() -> None:
    """``BridleDenied`` subclasses the built-in ``PermissionError`` so existing
    ``except PermissionError`` handlers catch a leash denial."""
    assert issubclass(agent_bridle.BridleDenied, PermissionError)
    with pytest.raises(PermissionError):
        agent_bridle.invoke("shell", {"program": "rm", "args": ["-rf", "/tmp/x"]}, ECHO_ONLY)


def test_unknown_tool_raises_bridle_denied() -> None:
    """A registry miss surfaces uniformly as ``BridleDenied``."""
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("no_such_tool", {}, ECHO_ONLY)


def test_tool_definitions_have_name_and_schema() -> None:
    """``tool_definitions()`` returns one MCP ``tools/list`` dict per tool, and
    the ``shell`` tool's input schema is stable across the stub/confined change:
    it still exposes BOTH shapes (argv ``program`` and free-form ``cmd``)."""
    defs = agent_bridle.tool_definitions()
    assert isinstance(defs, list) and defs
    shell = next(d for d in defs if d["name"] == "shell")
    assert isinstance(shell["inputSchema"], dict)
    props = shell["inputSchema"]["properties"]
    assert "program" in props
    assert "cmd" in props


def test_unknown_caveats_field_is_value_error() -> None:
    """A typo'd caveats axis is surfaced as a ``ValueError`` (bad input), NOT a
    silent no-op and NOT a ``BridleDenied`` (the grant is malformed, not an
    authority refusal). This is validated before the tool policy is consulted."""
    with pytest.raises(ValueError):
        agent_bridle.invoke(
            "shell",
            {"program": "echo", "args": ["x"]},
            {"exce": {"only": ["echo"]}},  # typo: exce
        )


def test_max_calls_budget_denies_within_one_grant() -> None:
    """``max_calls`` is enforced at the gate (before the tool policy): a grant of
    ``{"at_most": 0}`` is exhausted by the per-dispatch charge, so the dispatch
    is denied at the budget check."""
    grant = {"exec": {"only": ["echo"]}, "max_calls": {"at_most": 0}}
    with pytest.raises(agent_bridle.BridleDenied):
        agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, grant)
