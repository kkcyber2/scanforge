"""Command line for the orchestrator.

    scanforge list
    scanforge run --target example.com
    scanforge run --target example.com --checks unfinished_markers \\
        --option root=./src --out run.json

Exit codes: 0 complete, 1 usage error, 3 partial (some checks failed/timed out).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from sentinel_findings.render.html import render_html
from sentinel_findings.schema import FindingCollection

from .orchestrator import Orchestrator, RunStatus
from .registry import registry

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PARTIAL = 3


def _parse_options(pairs: Optional[List[str]]) -> Dict[str, Any]:
    """Parse repeated ``key=value`` into a dict, JSON-decoding values that parse."""
    out: Dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"error: --option expects key=value, got {pair!r}")
        key, _, raw = pair.partition("=")
        try:
            out[key] = json.loads(raw)
        except json.JSONDecodeError:
            out[key] = raw
    return out


def cmd_list(_: argparse.Namespace) -> int:
    from .checks import builtin  # noqa: F401  ensure registration

    for spec in registry.specs():
        print(f"{spec.name:22} {spec.category:15} w={spec.weight}  {spec.description}")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    from .checks import builtin  # noqa: F401

    options = _parse_options(args.option)
    orch = Orchestrator(
        check_timeout_s=args.timeout,
        max_retries=args.retries,
        max_workers=args.workers,
    )
    result = orch.run(
        args.target,
        checks=args.checks or None,
        options=options,
        scan_id=args.scan_id,
    )

    doc = result.to_dict()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        if not args.quiet:
            print(f"wrote {args.out}", file=sys.stderr)
    else:
        json.dump(doc, sys.stdout, indent=2)
        sys.stdout.write("\n")

    if not args.quiet:
        cov = doc["coverage"]
        print(
            f"{result.status.value}: {cov['ran']}/{cov['planned']} checks ran, "
            f"{result.findings.total} findings "
            f"({result.findings.counts})",
            file=sys.stderr,
        )
        if cov["failed"] or cov["timed_out"]:
            print(
                f"  incomplete: {cov['failed']} failed, {cov['timed_out']} timed out",
                file=sys.stderr,
            )

    return EXIT_OK if result.status is RunStatus.COMPLETE else EXIT_PARTIAL


def cmd_report(args: argparse.Namespace) -> int:
    with open(args.infile, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    collection = FindingCollection.from_dict({"findings": doc.get("findings", [])})
    cov = doc.get("coverage", {})
    if cov.get("complete") is False:
        print(
            "warning: this run was incomplete "
            f"({cov.get('failed', 0)} failed, {cov.get('timed_out', 0)} timed out); "
            "the report will say so.",
            file=sys.stderr,
        )
    html = render_html(
        collection,
        title=args.title,
        target=doc.get("target", ""),
        generated_at=doc.get("finished_at", ""),
    )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(html)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanforge", description="Scan orchestration: plan, run, aggregate."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="list registered checks")
    lst.set_defaults(func=cmd_list)

    run = sub.add_parser("run", help="run a plan against a target")
    run.add_argument("--target", required=True)
    run.add_argument("--checks", nargs="*", help="check names; default is all")
    run.add_argument("--option", action="append", help="key=value, repeatable")
    run.add_argument("--out", help="write JSON here")
    run.add_argument("--timeout", type=float, default=30.0)
    run.add_argument("--retries", type=int, default=1)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--scan-id", default="")
    run.add_argument("-q", "--quiet", action="store_true")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", help="render a run JSON to HTML")
    rep.add_argument("infile")
    rep.add_argument("--out")
    rep.add_argument("--title", default="Security Assessment")
    rep.set_defaults(func=cmd_report)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
