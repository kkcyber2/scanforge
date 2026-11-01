"""Built-in checks.

These are not demo stubs. Each one does something with a real, deterministic
input and produces canonical findings:

``engine_contract``   compares ForgeGuard's expected engine surface against the
                      routes the engine actually exposes. This is the check that
                      would have caught "11 routes, 8 wired" mechanically.
``scope_declaration`` flags a target with no verifiable authorization record.
``unfinished_markers``
                      scans a source tree for TODO/FIXME/HACK markers.
                      LANDMINE WARNING: ForgeGuard has **zero** TODO markers in
                      77,131 lines. Do not read a clean result here as "the work
                      is finished" — it is evidence that unfinished work is
                      unmarked, which is a different and worse finding.
``simulation_exposure``
                      finds a code path that can emit results without measuring
                      the target.

Every check declares its own limitations in its docstring, because a check that
does not say what it cannot see will be trusted for more than it can do.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sentinel_findings.schema import Confidence, Finding, Provenance, Severity

from ..registry import CheckContext, CheckFailed, CheckSkipped, registry

# --------------------------------------------------------------------------- #
# Engine contract                                                              #
# --------------------------------------------------------------------------- #

# The routes the engine exposes, read from agathon/orchestrator.py at HEAD
# (18 routes). Hard-coded on purpose: this list is the *expected* surface, and
# reading it from the engine at run time would make the check compare the
# engine to itself.
ENGINE_ROUTES: Dict[str, str] = {
    "GET /": "service banner",
    "GET /health": "health probe",
    "GET /healthz": "health probe (alt)",
    "GET /evolve/stats": "evolution telemetry",
    "POST /scan/start": "start a scan",
    "POST /scan/cancel/{scan_id}": "cancel a running scan",
    "POST /scan/{scan_id}/escalation": "resolve a pending escalation",
    "GET /scan/{scan_id}/state": "poll scan progress",
    "POST /recon/start": "start recon",
    "GET /recon/{recon_id}/status": "poll recon",
    "POST /identity/ocr": "identity document OCR",
    "POST /developer/test-probe": "developer probe",
    "POST /forge/execute": "forge execution",
    "POST /forge/kill": "forge teardown",
    "POST /bazaar/audit/{script_id}": "bazaar script audit",
    "GET /war-machine/leads": "war-machine leads",
    "GET /favicon.ico": "static",
    "GET /robots.txt": "static",
}

# Routes that are infrastructure rather than product capability. The app is
# not expected to call these, so reporting them as "capability not delivered"
# is noise that buries the real findings.
INFRA_ROUTES: Set[str] = {
    "GET /",
    "GET /health",
    "GET /healthz",
    "GET /favicon.ico",
    "GET /robots.txt",
    "GET /evolve/stats",
}

# Routes the app must call for the product flows to be complete. Derived from
# the audit: cancel and state are implemented engine-side and unreachable
# app-side, which is why a user has no exit from a hanging scan.
REQUIRED_CALLERS: Dict[str, str] = {
    "POST /scan/start": "src/lib/runner/runner.ts",
    "POST /scan/cancel/{scan_id}": "src/app/api/scan/cancel/route.ts",
    "GET /scan/{scan_id}/state": "src/app/api/scan/[id]/state/route.ts",
}


@registry.register(
    "engine_contract",
    category="integration",
    weight=1,
    description="ForgeGuard's expected engine surface vs what the engine exposes",
)
def engine_contract(ctx: CheckContext) -> List[Finding]:
    """Compare an engine route listing against ForgeGuard's expectations.

    Input (via ``ctx.options``):
      ``engine_routes``  list of "METHOD /path" strings the engine actually
                         exposes (as parsed from its OpenAPI or source).
      ``app_calls``      optional list of "METHOD /path" the app actually calls.

    Limitations: this checks *surface shape*, not behaviour. A route that
    exists and returns 500 is still "present" here. It cannot tell you a route
    is broken, only that it is missing or unused.
    """
    engine_routes = ctx.option("engine_routes")
    if engine_routes is None:
        raise CheckSkipped(
            "no engine_routes supplied; pass --option engine_routes=<json list>"
        )

    # Kept as the raw strings the caller supplied. Normalising first would
    # stamp a default GET onto bare paths and destroy the "method unstated"
    # wildcard that _route_present relies on.
    exposed = list(engine_routes)
    app_calls = list(ctx.option("app_calls") or [])
    expected = list(ENGINE_ROUTES)

    out: List[Finding] = []

    # 1. Routes the app needs but the engine does not have.
    for route in sorted(expected):
        if _route_present(route, exposed):
            continue
        if route in REQUIRED_CALLERS or "scan" in route:
            out.append(
                Finding(
                    id="",
                    title=f"Engine route missing: {route}",
                    severity=Severity.HIGH,
                    provenance=Provenance.OBSERVED,
                    category="integration",
                    description=(
                        f"ForgeGuard expects the engine to expose {route} "
                        f"({ENGINE_ROUTES.get(route, '')}) and it does not. "
                        "Any app flow that calls it will fail at runtime."
                    ),
                    location=route,
                    cwe=["CWE-1059"],  # incomplete design
                    confidence=Confidence.HIGH,
                    remediation=[
                        f"Add {route} to the engine, or remove the app-side caller.",
                        "Add this comparison to CI so the two surfaces cannot drift "
                        "again unnoticed.",
                    ],
                    tool="engine_contract",
                    target=ctx.target,
                )
            )

    # 2. Routes the engine exposes that nothing calls.
    if app_calls:
        for route in sorted(expected):
            if route in INFRA_ROUTES:
                continue
            if not _route_present(route, exposed):
                continue
            if _route_present(route, app_calls):
                continue
            out.append(
                Finding(
                    id="",
                    title=f"Engine route unreachable from the app: {route}",
                    severity=Severity.MEDIUM,
                    provenance=Provenance.OBSERVED,
                    category="integration",
                    description=(
                        f"The engine implements {route} but no app code calls it. "
                        "The capability is paid for and not delivered."
                    ),
                    location=route,
                    cwe=["CWE-1059"],
                    confidence=Confidence.HIGH,
                    remediation=[
                        f"Wire {route} into the app, or remove it from the engine.",
                        "Unwired routes are how a user ends up with no way to "
                        "cancel a hung scan.",
                    ],
                    tool="engine_contract",
                    target=ctx.target,
                )
            )

    # 3. Routes the app calls that nobody declared — drift in the other direction.
    if app_calls:
        for route in sorted(app_calls):
            if _route_present(route, expected) or _route_present(route, exposed):
                continue
            out.append(
                Finding(
                    id="",
                    title=f"App calls undeclared engine route: {route}",
                    severity=Severity.MEDIUM,
                    provenance=Provenance.OBSERVED,
                    category="integration",
                    description=(
                        f"The app calls {route}, which is neither in the expected "
                        "surface nor present on the engine. This will 404."
                    ),
                    location=route,
                    cwe=["CWE-1059"],
                    confidence=Confidence.HIGH,
                    remediation=["Implement the route or remove the call."],
                    tool="engine_contract",
                    target=ctx.target,
                )
            )

    return out


def _split_route(route: str) -> Tuple[Optional[str], str]:
    """Split into (method or None, normalised path).

    ``None`` means the caller did not state a method. That distinction matters:
    defaulting an unstated method to GET makes a real ``POST /scan/start`` look
    missing, and a contract checker that invents missing routes is worse than
    no checker at all.
    """
    raw = str(route).strip()
    parts = raw.split(None, 1)
    method: Optional[str] = None
    if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        method, raw = parts[0].upper(), parts[1].strip()
    path = re.sub(r"\{[^}]*\}", "{id}", raw)
    return method, path


def _route_present(route: str, exposed: Iterable[str]) -> bool:
    """True when ``route`` is served, treating an unstated method as a wildcard."""
    m, p = _split_route(route)
    for cand in exposed:
        cm, cp = _split_route(cand)
        if cp != p:
            continue
        if m is None or cm is None or m == cm:
            return True
    return False


def _exposed_matching(route: str, exposed: Iterable[str]) -> Optional[str]:
    """Return the first exposed route that satisfies ``route``, or None."""
    m, p = _split_route(route)
    for cand in exposed:
        cm, cp = _split_route(cand)
        if cp == p and (m is None or cm is None or m == cm):
            return cand
    return None


# --------------------------------------------------------------------------- #
# Scope declaration                                                            #
# --------------------------------------------------------------------------- #


@registry.register(
    "scope_declaration",
    category="authorization",
    weight=1,
    description="Target must carry a verifiable authorization record before any check runs",
)
def scope_declaration(ctx: CheckContext) -> List[Finding]:
    """Fail the scan when the target has no authorization assertion on record.

    This is the app-side counterpart to scopeguard's allowlist: scopeguard
    decides *whether* a host is in scope, this records *that a human asserted
    the right to test it*. Both are needed — an allowlisted host with no
    assertion is a host someone listed.

    Limitations: it verifies the presence and shape of a declaration, not that
    the declaration is true. Authorization is a legal act, not something a
    program can confirm.
    """
    decl = ctx.option("authorization")
    if not decl:
        raise CheckSkipped("no authorization record supplied")

    if not isinstance(decl, dict):
        raise CheckFailed(f"authorization record is {type(decl).__name__}, expected object")

    out: List[Finding] = []
    required = ("signer", "asserted_at", "target")
    missing = [k for k in required if not str(decl.get(k) or "").strip()]
    if missing:
        out.append(
            Finding(
                id="",
                title="Authorization record is incomplete",
                severity=Severity.CRITICAL,
                provenance=Provenance.OBSERVED,
                category="authorization",
                description=(
                    "An authorization record exists but is missing "
                    + ", ".join(missing)
                    + ". A partial record is not an assertion."
                ),
                location=ctx.target,
                cwe=["CWE-285"],
                confidence=Confidence.HIGH,
                remediation=[
                    "Require signer, asserted_at and target before allowing a scan.",
                    "Reject the record rather than filling gaps with defaults.",
                ],
                tool="scope_declaration",
                target=ctx.target,
            )
        )
        return out

    declared_target = str(decl.get("target") or "").strip()
    if declared_target and declared_target != ctx.target:
        out.append(
            Finding(
                id="",
                title="Authorization is for a different target",
                severity=Severity.CRITICAL,
                provenance=Provenance.OBSERVED,
                category="authorization",
                description=(
                    f"Authorization names {declared_target!r} but the scan target is "
                    f"{ctx.target!r}. Running would test a host nobody authorized."
                ),
                location=ctx.target,
                cwe=["CWE-285"],
                confidence=Confidence.HIGH,
                remediation=[
                    "Abort the scan.",
                    "Re-request authorization scoped to the actual target.",
                ],
                tool="scope_declaration",
                target=ctx.target,
            )
        )

    return out


# --------------------------------------------------------------------------- #
# Unfinished-work markers                                                      #
# --------------------------------------------------------------------------- #

_MARKER_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX|TBD)\b")
_TEXT_SUFFIXES = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs",
    ".java", ".rb", ".php", ".cs", ".sql", ".sh", ".yml", ".yaml",
}


@registry.register(
    "unfinished_markers",
    category="code-quality",
    weight=2,
    description="Count TODO/FIXME/HACK markers in a source tree",
)
def unfinished_markers(ctx: CheckContext) -> List[Finding]:
    """Scan a directory for unfinished-work markers.

    A *zero* result is a finding in its own right, not a clean bill of health.
    On ForgeGuard this check returns zero across 77,131 lines, and that is the
    single most useful thing it says: unfinished work there is unmarked, so it
    cannot be found by searching. The check emits an explicit MEDIUM finding to
    that effect so nobody reads the zero as "done".

    Limitations: comments only. A marker inside a string literal counts too
    (deliberate — it is still a marker a human left). It cannot see a stub that
    was never annotated.
    """
    root = ctx.option("root")
    if not root:
        raise CheckSkipped("no root supplied")
    if not os.path.isdir(root):
        raise CheckFailed(f"root {root!r} is not a directory")

    limit = int(ctx.option("max_files", 20000))
    hits: List[str] = []
    scanned = 0
    skipped_binary = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "node_modules", ".next", "dist", "build", "__pycache__"}
        ]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_SUFFIXES:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, "r", encoding="utf-8", errors="strict") as fh:
                    scanned += 1
                    if scanned > limit:
                        raise CheckSkipped(f"file limit {limit} reached")
                    for lineno, line in enumerate(fh, 1):
                        if _MARKER_RE.search(line):
                            rel = os.path.relpath(path, root)
                            hits.append(f"{rel}:{lineno}")
            except (UnicodeDecodeError, OSError):
                skipped_binary += 1
                continue

    out: List[Finding] = []
    if hits:
        out.append(
            Finding(
                id="",
                title=f"{len(hits)} unfinished-work marker(s) across {scanned} files",
                severity=Severity.LOW,
                provenance=Provenance.OBSERVED,
                category="code-quality",
                description=(
                    f"Found {len(hits)} TODO/FIXME/HACK/XXX/TBD markers. "
                    f"Scanned {scanned} text files; {skipped_binary} skipped as "
                    "unreadable or binary."
                ),
                evidence="\n".join(hits[:40]) + ("\n..." if len(hits) > 40 else ""),
                location=root,
                cwe=[],
                confidence=Confidence.HIGH,
                remediation=[
                    "Triage markers into issues, then delete the comment.",
                    "A marker older than a quarter is a decision nobody made.",
                ],
                tool="unfinished_markers",
                target=ctx.target,
            )
        )
    else:
        out.append(
            Finding(
                id="",
                title=(
                    f"Zero unfinished-work markers across {scanned} files "
                    "\u2014 read this as a warning, not a clean result"
                ),
                severity=Severity.MEDIUM,
                provenance=Provenance.OBSERVED,
                category="code-quality",
                description=(
                    "No TODO/FIXME/HACK/XXX/TBD markers were found. On a codebase "
                    "with known incomplete flows this means the incomplete work is "
                    "unmarked: it ships behind a UI that looks finished. Absence of "
                    "markers is not absence of unfinished work, and searching for "
                    "them will not find it."
                ),
                evidence=f"scanned {scanned} text files, 0 markers",
                location=root,
                cwe=["CWE-1059"],
                confidence=Confidence.HIGH,
                remediation=[
                    "Do not use a marker scan as a completeness check on this repo.",
                    "Audit flows by exercising them, not by grepping.",
                    "When you do find a stub, mark it immediately.",
                ],
                tool="unfinished_markers",
                target=ctx.target,
            )
        )

    return out


# --------------------------------------------------------------------------- #
# Simulation-mode exposure                                                     #
# --------------------------------------------------------------------------- #


@registry.register(
    "simulation_exposure",
    category="honesty",
    weight=1,
    description="Detect a codebase that can silently return simulated results",
)
def simulation_exposure(ctx: CheckContext) -> List[Finding]:
    """Flag a code path that can produce findings without touching the target.

    ForgeGuard ships ``src/lib/runner/synthetic.ts`` — a generator that emits
    the same event shape as the real runner and is selected when the Python
    toolkit is absent. That is defensible for CI. It becomes a product risk when
    the resulting scan looks identical to a real one downstream.

    Limitations: it detects the *pattern* (a synthetic/simulated module reachable
    from a runner). It cannot decide whether the flag is set in production —
    that requires reading the deployed environment, which is out of scope for a
    static check.
    """
    root = ctx.option("root")
    if not root:
        raise CheckSkipped("no root supplied")
    if not os.path.isdir(root):
        raise CheckFailed(f"root {root!r} is not a directory")

    patterns = ("synthetic", "simulat", "fixture", "mock_scan", "fake_scan")
    # Content markers catch the dangerous case a filename scan misses entirely:
    # a simulation branch living inside a normally-named module such as
    # runner/runner.ts. Filename-only detection would report "clean" for a
    # codebase whose runner returns fabricated results behind an env flag.
    content_markers = (
        "REVENUE_SIMULATION_MODE",
        "SIMULATION_MODE",
        "USE_SYNTHETIC",
        "syntheticFindings",
        "generateSynthetic",
        "fakeResults",
    )
    DEPRECATED_MARKERS = ("@deprecated", "DEPRECATED", "deprecated:")
    hits: List[Tuple[str, bool]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".next", "dist"}]
        for name in filenames:
            lower = name.lower()
            suffix = os.path.splitext(lower)[1]
            if suffix not in _TEXT_SUFFIXES:
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            if any(p in lower for p in patterns):
                hits.append((rel, False))
                continue
            # Only read files that could plausibly carry a flag.
            try:
                if os.path.getsize(os.path.join(dirpath, name)) > 512 * 1024:
                    continue
                with open(os.path.join(dirpath, name), "r", encoding="utf-8", errors="ignore") as fh:
                    body = fh.read()
            except OSError:
                continue
            if any(m in body for m in content_markers):
                # A file that documents the flag in a comment is not the same
                # as one that branches on it. DEPRECATED_MARKERS downgrades a
                # legacy module rather than reporting it at the same severity
                # as a live switch, because a report that cannot tell those
                # apart trains the reader to ignore it.
                legacy = any(m in body for m in DEPRECATED_MARKERS)
                hits.append((rel, legacy))

    out: List[Finding] = []
    for rel, legacy in sorted(set(hits)):
        out.append(
            Finding(
                id="",
                title=(
                    f"Deprecated module still references a simulation flag: {rel}"
                    if legacy
                    else f"Simulated-result module present: {rel}"
                ),
                severity=Severity.LOW if legacy else Severity.HIGH,
                provenance=Provenance.OBSERVED,
                category="honesty",
                description=(
                    f"{rel} is marked deprecated but still references a simulation "
                    "flag. Dead code that can still be selected is a trap: it looks "
                    "unreachable and is one import away from running."
                    if legacy
                    else (
                        f"{rel} appears to generate results rather than measure them. If "
                        "it can be selected at run time, a scan can return findings that "
                        "were never observed. Every finding it produces must carry "
                        "provenance=simulated all the way to the report."
                    )
                ),
                location=rel,
                cwe=["CWE-1059"],
                confidence=Confidence.MEDIUM,
                remediation=(
                    ["Delete the module, or make it fail closed outside development."]
                    if legacy
                    else [
                        "Tag every generated finding with an explicit simulated flag.",
                        "Make the report renderer refuse a client document containing "
                        "simulated findings unless the caller acknowledges it.",
                        "Gate the module behind NODE_ENV !== 'production'.",
                    ]
                ),
                tool="simulation_exposure",
                target=ctx.target,
            )
        )
    return out
