"""Orchestrator behaviour: timeouts, isolation, retries, accounting."""

from __future__ import annotations

import threading
import time

import pytest

from scanforge.orchestrator import CheckStatus, Orchestrator, RunStatus
from scanforge.registry import CheckFailed, CheckSkipped, CheckSpec, Registry
from sentinel_findings.schema import Finding, Provenance, Severity


def _finding(title: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        id="",
        title=title,
        severity=severity,
        provenance=Provenance.OBSERVED,
        tool="test",
    )


def _reg(*specs: CheckSpec) -> Registry:
    r = Registry()
    for s in specs:
        r.add(s)
    return r


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #


def test_register_then_get():
    r = Registry()
    r.add(CheckSpec(name="a", fn=lambda ctx: []))
    assert r.names() == ["a"]
    assert r.get("a").name == "a"


def test_duplicate_registration_rejected():
    r = Registry()
    r.add(CheckSpec(name="a", fn=lambda ctx: []))
    with pytest.raises(ValueError, match="already registered"):
        r.add(CheckSpec(name="a", fn=lambda ctx: []))


def test_unknown_check_raises_with_available_names():
    r = Registry()
    r.add(CheckSpec(name="alpha", fn=lambda ctx: []))
    with pytest.raises(KeyError, match="alpha"):
        r.get("beta")


def test_plan_orders_cheapest_first():
    r = _reg(
        CheckSpec(name="slow", fn=lambda ctx: [], weight=9),
        CheckSpec(name="fast", fn=lambda ctx: [], weight=1),
        CheckSpec(name="mid", fn=lambda ctx: [], weight=5),
    )
    assert [s.name for s in r.plan()] == ["fast", "mid", "slow"]


def test_plan_with_requested_subset():
    r = _reg(
        CheckSpec(name="a", fn=lambda ctx: [], weight=2),
        CheckSpec(name="b", fn=lambda ctx: [], weight=1),
    )
    assert [s.name for s in r.plan(["a"])] == ["a"]


def test_decorator_registration():
    r = Registry()

    @r.register("deco", category="x")
    def _check(ctx):
        """Docstring becomes the description."""
        return []

    spec = r.get("deco")
    assert spec.category == "x"
    assert spec.description == "Docstring becomes the description."


# --------------------------------------------------------------------------- #
# Happy path                                                                   #
# --------------------------------------------------------------------------- #


def test_single_check_findings_aggregate():
    r = _reg(CheckSpec(name="one", fn=lambda ctx: [_finding("f1"), _finding("f2")]))
    out = Orchestrator(reg=r).run("example.com")
    assert out.findings.total == 2
    assert out.status is RunStatus.COMPLETE
    assert out.ran == 1
    assert out.incomplete is False


def test_run_records_target_and_timestamps():
    r = _reg(CheckSpec(name="one", fn=lambda ctx: []))
    out = Orchestrator(reg=r).run("host.example")
    assert out.target == "host.example"
    assert out.started_at and out.finished_at
    assert out.run_id


def test_scan_id_is_reused_as_run_id():
    r = _reg(CheckSpec(name="one", fn=lambda ctx: []))
    out = Orchestrator(reg=r).run("h", scan_id="abc123")
    assert out.run_id == "abc123"


def test_empty_result_is_complete_not_failed():
    r = _reg(CheckSpec(name="clean", fn=lambda ctx: []))
    out = Orchestrator(reg=r).run("h")
    assert out.status is RunStatus.COMPLETE
    assert out.findings.total == 0


def test_check_receives_context():
    seen = {}

    def _c(ctx):
        seen["target"] = ctx.target
        seen["scan_id"] = ctx.scan_id
        seen["opt"] = ctx.options.get("k")
        return []

    r = _reg(CheckSpec(name="ctx", fn=_c))
    Orchestrator(reg=r).run("t.example", options={"k": 7}, scan_id="s1")
    assert seen["target"] == "t.example"
    assert seen["scan_id"] == "s1"
    assert seen["opt"] == 7


# --------------------------------------------------------------------------- #
# Failure isolation                                                            #
# --------------------------------------------------------------------------- #


def test_failing_check_does_not_stop_the_run():
    def _boom(ctx):
        raise RuntimeError("kaboom")

    r = _reg(
        CheckSpec(name="a_boom", fn=_boom, weight=1),
        CheckSpec(name="b_ok", fn=lambda ctx: [_finding("survived")], weight=2),
    )
    out = Orchestrator(reg=r).run("h")
    assert out.findings.total == 1
    assert out.failed == 1
    assert out.status is RunStatus.PARTIAL
    assert out.incomplete is True


def test_failure_is_recorded_with_type_and_message():
    def _boom(ctx):
        raise ValueError("bad input")

    r = _reg(CheckSpec(name="boom", fn=_boom))
    out = Orchestrator(reg=r, max_retries=0).run("h")
    c = out.checks[0]
    assert c.status is CheckStatus.FAILED
    assert c.error_type == "ValueError"
    assert "bad input" in c.error


def test_check_failed_exception_is_retried_then_captured():
    calls = {"n": 0}

    def _flaky(ctx):
        calls["n"] += 1
        raise CheckFailed("transient")

    r = _reg(CheckSpec(name="flaky", fn=_flaky))
    out = Orchestrator(reg=r, max_retries=2).run("h")
    assert calls["n"] == 3  # 1 attempt + 2 retries
    assert out.checks[0].attempts == 3
    assert out.checks[0].status is CheckStatus.FAILED


def test_retry_recovers_a_transient_failure():
    calls = {"n": 0}

    def _flaky(ctx):
        calls["n"] += 1
        if calls["n"] == 1:
            raise CheckFailed("first time")
        return [_finding("recovered")]

    r = _reg(CheckSpec(name="flaky", fn=_flaky))
    out = Orchestrator(reg=r, max_retries=2).run("h")
    assert out.findings.total == 1
    assert out.checks[0].status is CheckStatus.PASSED
    assert out.status is RunStatus.COMPLETE


def test_skipped_is_not_an_error():
    def _skip(ctx):
        raise CheckSkipped("no credential")

    r = _reg(CheckSpec(name="skip", fn=_skip))
    out = Orchestrator(reg=r).run("h")
    assert out.checks[0].status is CheckStatus.SKIPPED
    assert out.checks[0].skipped_reason == "no credential"
    # Skipped must not make the run partial: it is a legitimate outcome.
    assert out.status is RunStatus.COMPLETE
    assert out.skipped == 1


def test_skipped_is_not_retried():
    calls = {"n": 0}

    def _skip(ctx):
        calls["n"] += 1
        raise CheckSkipped("always")

    r = _reg(CheckSpec(name="skip", fn=_skip))
    Orchestrator(reg=r, max_retries=3).run("h")
    assert calls["n"] == 1


# --------------------------------------------------------------------------- #
# Timeouts                                                                     #
# --------------------------------------------------------------------------- #


def test_timeout_is_enforced_and_recorded():
    def _hang(ctx):
        time.sleep(3)
        return []

    r = _reg(CheckSpec(name="hang", fn=_hang))
    t0 = time.monotonic()
    out = Orchestrator(reg=r, check_timeout_s=0.3, max_retries=0).run("h")
    elapsed = time.monotonic() - t0

    assert out.checks[0].status is CheckStatus.TIMED_OUT
    assert out.timed_out == 1
    assert out.status is RunStatus.PARTIAL
    assert elapsed < 2.0, "orchestrator waited for the hung check instead of abandoning it"


def test_timeout_is_not_retried_by_default():
    calls = {"n": 0}
    lock = threading.Lock()

    def _hang(ctx):
        with lock:
            calls["n"] += 1
        time.sleep(2)
        return []

    r = _reg(CheckSpec(name="hang", fn=_hang))
    Orchestrator(reg=r, check_timeout_s=0.2, max_retries=1).run("h")
    # A timeout returns immediately rather than retrying, so still 1.
    assert calls["n"] == 1


def test_fast_checks_after_a_timeout_still_run():
    def _hang(ctx):
        time.sleep(2)
        return []

    r = _reg(
        CheckSpec(name="a_hang", fn=_hang, weight=1),
        CheckSpec(name="b_fast", fn=lambda ctx: [_finding("ok")], weight=2),
    )
    out = Orchestrator(reg=r, check_timeout_s=0.25, max_retries=0).run("h")
    assert out.findings.total == 1
    assert out.timed_out == 1


# --------------------------------------------------------------------------- #
# Return-value normalisation                                                   #
# --------------------------------------------------------------------------- #


def test_none_return_is_empty():
    r = _reg(CheckSpec(name="n", fn=lambda ctx: None))
    assert Orchestrator(reg=r).run("h").findings.total == 0


def test_single_finding_not_in_a_list_is_accepted():
    r = _reg(CheckSpec(name="one", fn=lambda ctx: _finding("solo")))
    out = Orchestrator(reg=r).run("h")
    assert out.findings.total == 1


def test_dict_return_is_coerced():
    def _d(ctx):
        return {"title": "from dict", "severity": "high", "provenance": "observed"}

    r = _reg(CheckSpec(name="d", fn=_d))
    out = Orchestrator(reg=r).run("h")
    assert out.findings.total == 1
    assert out.findings.sorted()[0].severity is Severity.HIGH


def test_bad_return_type_is_a_check_failure_not_a_crash():
    r = _reg(CheckSpec(name="bad", fn=lambda ctx: [42]))
    out = Orchestrator(reg=r, max_retries=0).run("h")
    assert out.checks[0].status is CheckStatus.FAILED
    assert out.checks[0].error_type == "TypeError"


def test_dedupes_across_checks_using_fingerprint():
    r = _reg(
        CheckSpec(
            name="a",
            fn=lambda ctx: [
                Finding(
                    id="",
                    title="identical issue",
                    severity=Severity.HIGH,
                    category="tls",
                    location="h:443",
                    tool="t1",
                    provenance=Provenance.OBSERVED,
                )
            ],
            weight=1,
        ),
        CheckSpec(
            name="b",
            fn=lambda ctx: [
                Finding(
                    id="",
                    title="identical issue",
                    severity=Severity.CRITICAL,
                    category="tls",
                    location="h:443",
                    tool="t1",
                    provenance=Provenance.OBSERVED,
                )
            ],
            weight=2,
        ),
    )
    out = Orchestrator(reg=r).run("h")
    assert out.findings.total == 1
    assert out.findings.sorted()[0].severity is Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Serialisation                                                                #
# --------------------------------------------------------------------------- #


def test_to_dict_has_coverage_block():
    def _skip(ctx):
        raise CheckSkipped("n")

    r = _reg(
        CheckSpec(name="ok", fn=lambda ctx: [_finding("x")], weight=1),
        CheckSpec(name="skip", fn=_skip, weight=2),
    )
    doc = Orchestrator(reg=r).run("h").to_dict()
    cov = doc["coverage"]
    assert cov["planned"] == 2
    assert cov["ran"] == 1
    assert cov["skipped"] == 1
    assert cov["complete"] is True


def test_to_dict_flags_incomplete_coverage():
    def _boom(ctx):
        raise RuntimeError("x")

    r = _reg(CheckSpec(name="boom", fn=_boom))
    cov = Orchestrator(reg=r, max_retries=0).run("h").to_dict()["coverage"]
    assert cov["complete"] is False
    assert cov["failed"] == 1


def test_to_dict_is_json_serialisable():
    import json

    r = _reg(CheckSpec(name="ok", fn=lambda ctx: [_finding("x")]))
    blob = json.dumps(Orchestrator(reg=r).run("h").to_dict())
    assert '"coverage"' in blob


def test_event_callback_receives_lifecycle():
    events = []
    r = _reg(CheckSpec(name="ok", fn=lambda ctx: []))
    Orchestrator(reg=r).run("h", on_event=lambda kind, payload: events.append(kind))
    assert events[0] == "start"
    assert "check_start" in events
    assert "check_done" in events
    assert events[-1] == "finish"
