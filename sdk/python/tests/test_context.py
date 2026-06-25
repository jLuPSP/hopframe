"""Tests for ambient agent-run-id propagation and the httpx hook."""

from __future__ import annotations

from hopframe import (
    RUN_ID_HEADER,
    Hopframe,
    current_run_id,
    new_run_id,
    run_id_headers,
    run_scope,
)
from hopframe.context import reset_run_id, set_run_id
from hopframe.integrations.httpx import instrument, run_id_request_hook


def test_default_is_empty():
    assert current_run_id() == ""
    assert run_id_headers() == {}


def test_scope_sets_and_resets():
    assert current_run_id() == ""
    with run_scope("run-x") as rid:
        assert rid == "run-x"
        assert current_run_id() == "run-x"
        assert run_id_headers()[RUN_ID_HEADER] == "run-x"
    assert current_run_id() == ""


def test_scope_mints_when_absent():
    with run_scope() as rid:
        assert rid and rid.startswith("run-")
        assert current_run_id() == rid
    assert current_run_id() == ""


def test_nesting_restores_outer():
    with run_scope("outer"):
        with run_scope("inner"):
            assert current_run_id() == "inner"
        assert current_run_id() == "outer"


def test_set_reset_primitives():
    token = set_run_id("manual")
    try:
        assert current_run_id() == "manual"
    finally:
        reset_run_id(token)
    assert current_run_id() == ""


def test_headers_merge_and_explicit_override():
    with run_scope("ambient"):
        h = run_id_headers({"Authorization": "Bearer t"})
        assert h["Authorization"] == "Bearer t"
        assert h[RUN_ID_HEADER] == "ambient"
        # an explicit run id wins over the ambient one
        assert run_id_headers(run_id="explicit")[RUN_ID_HEADER] == "explicit"
    # input mapping is not mutated
    base = {"a": "b"}
    run_id_headers(base, run_id="r")
    assert RUN_ID_HEADER not in base


def test_emit_defaults_to_ambient_run_id():
    hf = Hopframe("http://localhost:7090", async_delivery=False)
    with run_scope("run-emit"):
        ev = hf.new_event()
        assert ev.agent_run_id == "run-emit"
    # explicit still wins, and outside a scope it falls back to empty
    assert hf.new_event(agent_run_id="explicit").agent_run_id == "explicit"
    assert hf.new_event().agent_run_id == ""


class _Req:
    def __init__(self):
        self.headers = {}


def test_httpx_hook_stamps_under_scope_only():
    r = _Req()
    run_id_request_hook(r)  # no scope -> no header
    assert RUN_ID_HEADER not in r.headers
    with run_scope("run-h"):
        run_id_request_hook(r)
        assert r.headers[RUN_ID_HEADER] == "run-h"


def test_httpx_hook_does_not_overwrite_explicit_header():
    r = _Req()
    r.headers[RUN_ID_HEADER] = "preset"
    with run_scope("run-h"):
        run_id_request_hook(r)
    assert r.headers[RUN_ID_HEADER] == "preset"


class _Client:
    def __init__(self):
        self.event_hooks = {}


def test_instrument_adds_hook_idempotently_and_preserves_others():
    def other(_):  # pre-existing hook must survive
        pass

    c = _Client()
    c.event_hooks = {"request": [other]}
    instrument(c)
    instrument(c)
    hooks = c.event_hooks["request"]
    assert hooks.count(run_id_request_hook) == 1
    assert other in hooks


def test_new_run_id_shape():
    rid = new_run_id()
    assert rid.startswith("run-py-")
