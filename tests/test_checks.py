"""Built-in check tests.

The engine_contract tests exist because the matcher shipped two real bugs:
a bare path was normalised to GET (so a real POST looked missing), and
infrastructure routes were reported as undelivered capability. Both produced
findings that looked plausible and were wrong.
"""

from __future__ import annotations

import pytest

from scanforge.checks.builtin import (
    ENGINE_ROUTES,
    INFRA_ROUTES,
    _route_present,
    _split_route,
    engine_contract,
    simulation_exposure,
    unfinished_markers,
)
from scanforge.registry import CheckContext, CheckFailed, CheckSkipped
from sentinel_findings.schema import Severity


def _ctx(**options):
    return CheckContext(
        target="forgeguard.local",
        scan_id="t1",
        tool_name="engine_contract",
        options=options,
    )


ENGINE = [
    "/", "/bazaar/audit/{script_id}", "/developer/test-probe", "/evolve/stats",
    "/favicon.ico", "/forge/execute", "/forge/kill", "/health", "/healthz",
    "/identity/ocr", "/recon/start", "/recon/{recon_id}/status", "/robots.txt",
    "/scan/cancel/{scan_id}", "/scan/start", "/scan/{scan_id}/escalation",
    "/scan/{scan_id}/state", "/war-machine/leads",
]
APP = [
    "/scan/start", "/forge/execute", "/forge/kill", "/identity/ocr",
    "/recon/start", "/recon/{recon_id}/status", "/bazaar/audit/{script_id}",
]


# --------------------------------------------------------------------------- #
# Matcher                                                                      #
# --------------------------------------------------------------------------- #


def test_split_route_infers_no_method_for_bare_path():
    method, path = _split_route("/scan/start")
    assert method is None
    assert path == "/scan/start"


def test_split_route_keeps_explicit_method():
    assert _split_route("POST /scan/start") == ("POST", "/scan/start")


def test_split_route_normalises_path_params():
    assert _split_route("GET /scan/{scan_id}/state")[1] == "/scan/{id}/state"


def test_bare_path_matches_any_method():
    """The original bug: a bare path was assumed to be GET."""
    assert _route_present("POST /scan/start", ["/scan/start"]) is True
    assert _route_present("GET /scan/start", ["/scan/start"]) is True


def test_explicit_methods_do_not_cross_match():
    assert _route_present("POST /x", ["GET /x"]) is False
    assert _route_present("GET /x", ["POST /x"]) is False


def test_param_names_are_interchangeable():
    assert _route_present("GET /scan/{scan_id}/state", ["/scan/{id}/state"]) is True


def test_different_paths_do_not_match():
    assert _route_present("POST /scan/start", ["/scan/cancel"]) is False


# --------------------------------------------------------------------------- #
# engine_contract                                                              #
# --------------------------------------------------------------------------- #


def test_skips_without_engine_routes():
    with pytest.raises(CheckSkipped):
        engine_contract(_ctx())


def test_full_surface_reports_only_genuinely_unwired():
    """Against the real 18-route engine and the real call set."""
    found = engine_contract(_ctx(engine_routes=ENGINE, app_calls=APP))
    titles = sorted(f.title for f in found)

    # Nothing missing: the app does not expect routes the engine lacks.
    assert not [t for t in titles if "missing" in t], titles

    unwired = {f.location for f in found if "unreachable" in f.title}
    assert unwired == {
        "GET /scan/{scan_id}/state",
        "GET /war-machine/leads",
        "POST /developer/test-probe",
        "POST /scan/cancel/{scan_id}",
        "POST /scan/{scan_id}/escalation",
    }


def test_infra_routes_are_not_reported_as_undelivered():
    found = engine_contract(_ctx(engine_routes=ENGINE, app_calls=APP))
    for f in found:
        for infra in INFRA_ROUTES:
            assert f.location != infra, f"{infra} is infrastructure, not a feature"


def test_missing_route_is_reported_when_truly_absent():
    partial = [r for r in ENGINE if "cancel" not in r]
    found = engine_contract(_ctx(engine_routes=partial))
    missing = [f for f in found if "missing" in f.title]
    assert any("cancel" in f.location for f in missing)
    assert missing[0].severity is Severity.HIGH


def test_non_scan_missing_route_is_not_high():
    """Only routes that gate a scan flow are HIGH; the rest are not."""
    partial = [r for r in ENGINE if "identity/ocr" not in r]
    found = engine_contract(_ctx(engine_routes=partial))
    ocr = [f for f in found if "identity/ocr" in f.location and "missing" in f.title]
    assert ocr == []


def test_app_calling_undeclared_route_is_flagged():
    found = engine_contract(
        _ctx(engine_routes=ENGINE, app_calls=APP + ["POST /scan/halt"])
    )
    drift = [f for f in found if "undeclared" in f.title]
    assert len(drift) == 1
    assert "halt" in drift[0].location


def test_explicit_method_strings_also_work():
    """Callers who supply 'METHOD /path' must not be penalised."""
    post_paths = {"/scan/start", "/scan/cancel/{scan_id}", "/scan/{scan_id}/escalation",
                  "/recon/start", "/identity/ocr", "/developer/test-probe",
                  "/forge/execute", "/forge/kill", "/bazaar/audit/{script_id}"}
    explicit = [
        (f"POST {r}" if r in post_paths else f"GET {r}") for r in ENGINE
    ]
    found = engine_contract(_ctx(engine_routes=explicit, app_calls=APP))
    assert not [f for f in found if "missing" in f.title]


def test_all_findings_carry_target_and_cwe():
    for f in engine_contract(_ctx(engine_routes=ENGINE, app_calls=APP)):
        assert f.target == "forgeguard.local"
        assert "CWE-1059" in f.cwe
        assert f.provenance.value == "observed"


def test_expected_surface_is_eighteen_routes():
    assert len(ENGINE_ROUTES) == 18


# --------------------------------------------------------------------------- #
# scope_declaration                                                            #
# --------------------------------------------------------------------------- #


def test_scope_skips_without_authorization():
    from scanforge.checks.builtin import scope_declaration

    with pytest.raises(CheckSkipped):
        scope_declaration(_ctx())


def test_scope_complete_record_passes():
    from scanforge.checks.builtin import scope_declaration

    assert scope_declaration(
        _ctx(authorization={"signer": "A", "asserted_at": "2026-11-01",
                            "target": "forgeguard.local"})
    ) == []


def test_scope_partial_record_is_critical():
    from scanforge.checks.builtin import scope_declaration

    found = scope_declaration(_ctx(authorization={"signer": "A", "target": "forgeguard.local"}))
    assert found[0].severity is Severity.CRITICAL
    assert "asserted_at" in found[0].description


def test_scope_wrong_target_is_critical():
    from scanforge.checks.builtin import scope_declaration

    found = scope_declaration(
        _ctx(authorization={"signer": "A", "asserted_at": "x", "target": "other.test"})
    )
    assert found[0].severity is Severity.CRITICAL
    assert "different target" in found[0].title


def test_scope_non_dict_record_is_a_failure():
    from scanforge.checks.builtin import scope_declaration

    with pytest.raises(CheckFailed):
        scope_declaration(_ctx(authorization="yes"))


# --------------------------------------------------------------------------- #
# unfinished_markers                                                           #
# --------------------------------------------------------------------------- #


def test_zero_markers_is_itself_a_finding(tmp_path):
    """A large codebase with no TODOs has hidden unfinished work, not none."""
    (tmp_path / "a.py").write_text("x = 1\n" * 50)
    found = unfinished_markers(_ctx(root=str(tmp_path)))
    assert len(found) == 1
    assert found[0].severity is Severity.MEDIUM
    assert "warning" in found[0].title.lower() or "warning" in found[0].description.lower()


def test_markers_are_counted(tmp_path):
    (tmp_path / "a.py").write_text("# TODO: fix\n# FIXME: broken\n# HACK: here\n")
    found = unfinished_markers(_ctx(root=str(tmp_path)))
    assert found[0].severity is Severity.LOW
    assert "3 unfinished-work marker" in found[0].title
    assert "a.py" in found[0].evidence


def test_skips_without_root():
    with pytest.raises(CheckSkipped):
        unfinished_markers(_ctx())


def test_missing_root_is_a_failure():
    with pytest.raises(CheckFailed):
        unfinished_markers(_ctx(root="/nonexistent/path/xyz"))


# --------------------------------------------------------------------------- #
# simulation_exposure                                                          #
# --------------------------------------------------------------------------- #


def test_flags_simulation_flag(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "runner.ts").write_text(
        "const REVENUE_SIMULATION_MODE = process.env.REVENUE_SIMULATION_MODE === 'true';\n"
        "if (REVENUE_SIMULATION_MODE) { return syntheticFindings(); }\n"
    )
    found = simulation_exposure(_ctx(root=str(tmp_path)))
    assert found
    assert found[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert any("simulated" in r.lower() for r in found[0].remediation)


def test_clean_tree_has_no_finding(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.ts").write_text("export const x = 1;\n")
    assert simulation_exposure(_ctx(root=str(tmp_path))) == []


def test_deprecated_module_is_downgraded_not_dropped(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "legacy.ts").write_text(
        "/** @deprecated use runner2 */\n"
        "export const SIMULATION_MODE = true;\n"
    )
    found = simulation_exposure(_ctx(root=str(tmp_path)))
    assert found
    assert found[0].severity is Severity.LOW
    assert "deprecated" in found[0].title.lower()
