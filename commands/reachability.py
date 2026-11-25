"""CloudMapper command: internet -> sensitive resource reachability analysis."""
from __future__ import print_function

import argparse
import json
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# This module is intentionally importable without the heavy/pyjq dependent
# shared.common stack: the reachability engine itself is stdlib only.
from shared.reachability import (
    INTERNET_CIDR,
    IncrementalReachability,
    ReachabilityAnalyzer,
    render_json,
    render_markdown,
    render_text,
    topology_from_account_data,
)

__description__ = (
    "Analyze internet-to-sensitive-resource reachability through security "
    "group rules, with path reports and incremental rule updates"
)

DEFAULT_ACCOUNT_ROOTS = [
    "tests/fixtures/reachability/accounts",
    "account-data",
]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cloudmapper.py reachability",
        description=__description__,
    )
    parser.add_argument(
        "--graph", "--input",
        help="Path to a Cytoscape graph JSON (prepare.py / web/data.json format)",
    )
    parser.add_argument(
        "--accounts",
        help="Comma separated account names/directories to analyze",
    )
    parser.add_argument(
        "--account",
        dest="account_single",
        help="Single account name/directory (alias for --accounts NAME)",
    )
    parser.add_argument(
        "--account-root",
        action="append",
        default=[],
        help="Directory containing <account>/ topology or account-data snapshots "
        "(may be repeated)",
    )
    parser.add_argument("--port", type=int, help="Destination port to test")
    parser.add_argument("--protocol", help="Protocol to test (tcp/udp/icmp/all)")
    parser.add_argument(
        "--all-targets",
        action="store_true",
        help="Report paths to every reachable resource, not only sensitive ones",
    )
    parser.add_argument("--max-hops", type=int, default=6)
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
    )
    parser.add_argument("--json", action="store_true", help="Shorthand for --format json")
    parser.add_argument("--out", "--output", dest="out", help="Write the report to this file")
    parser.add_argument(
        "--web-overlay",
        nargs="?",
        const="web/reachability.json",
        help="Write a web visualization overlay (default: web/reachability.json)",
    )
    parser.add_argument(
        "--state",
        help="Path to the incremental update state file",
    )
    parser.add_argument(
        "--update-sg",
        action="append",
        default=[],
        metavar="ACCOUNT=FILE",
        help="Apply a changed security group document and print the path diff "
        "(may be repeated)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when reachable sensitive paths are found",
    )
    return parser


def resolve_account(name_or_path, extra_roots):
    if os.path.isdir(name_or_path):
        return name_or_path
    roots = list(extra_roots) + DEFAULT_ACCOUNT_ROOTS
    for root in roots:
        candidate = os.path.join(root, name_or_path)
        if os.path.isdir(candidate):
            return candidate
        if os.path.isfile(candidate + ".json"):
            return candidate + ".json"
    # Maybe it is a topology file directly.
    if os.path.isfile(name_or_path):
        return name_or_path
    raise SystemExit(
        "ERROR: account '{}' not found in: {}".format(
            name_or_path, ", ".join(roots)
        )
    )


def load_account_model(location, name):
    if os.path.isfile(location):
        return location  # analyzer dispatches topology/graph JSON itself
    topology_file = os.path.join(location, "topology.json")
    if os.path.isfile(topology_file):
        return topology_file
    return topology_from_account_data(location, name=name)


def _read_sg_change(spec):
    if "=" not in spec:
        raise SystemExit("ERROR: --update-sg expects ACCOUNT=FILE, got '{}'".format(spec))
    account, path = spec.split("=", 1)
    with open(path) as handle:
        document = json.load(handle)
    if isinstance(document, dict) and "SecurityGroups" in document:
        groups = document["SecurityGroups"]
        if len(groups) != 1:
            raise SystemExit(
                "ERROR: {} must contain exactly one security group".format(path)
            )
        document = groups[0]
    return account, document


def run(arguments):
    args = build_parser().parse_args(arguments)
    if getattr(args, "json", False):
        args.format = "json"
    if args.account_single and not args.accounts:
        args.accounts = args.account_single
    analyzer_options = {
        "port": args.port,
        "protocol": args.protocol,
        "sensitive_only": not args.all_targets,
        "max_hops": args.max_hops,
    }
    analyzer = ReachabilityAnalyzer(**analyzer_options)

    # Single graph file mode ------------------------------------------------
    if args.graph:
        report = analyzer.analyze(args.graph, name=args.accounts or None)
        _emit(report, args)
        _maybe_write_overlay(report, args)
        return _exit_code(report, args)

    if not args.accounts:
        raise SystemExit(
            "ERROR: provide --graph graph.json or --accounts a,b,c "
            "(see 'cloudmapper.py reachability --help')"
        )

    names = [item.strip() for item in args.accounts.split(",") if item.strip()]

    # Incremental state mode ------------------------------------------------
    if args.state:
        return _run_incremental(args, names, analyzer_options)

    # Plain multi-account analysis -----------------------------------------
    reports = []
    for name in names:
        location = resolve_account(name, args.account_root)
        source = load_account_model(location, name)
        reports.append(analyzer.analyze(source, name=name))

    combined = {
        "schema": "cloudmapper.reachability/v1+collection",
        "source": INTERNET_CIDR,
        "accounts": reports,
        "paths": [path for report in reports for path in report.paths],
    }
    _emit(combined, args)
    _maybe_write_overlay(combined, args)
    if args.check and any(report.summary["paths"] for report in reports):
        return 1
    return 0


def _run_incremental(args, names, analyzer_options):
    store = IncrementalReachability(state_path=args.state, **analyzer_options)
    for name in names:
        if name in store.accounts:
            continue
        location = resolve_account(name, args.account_root)
        store.add_account_from_directory(name, location)

    diffs = []
    for update_spec in args.update_sg:
        account, security_group = _read_sg_change(update_spec)
        if account not in store.accounts:
            raise SystemExit(
                "ERROR: account '{}' is not in the state; pass it via --accounts first".format(
                    account
                )
            )
        diff = store.update_security_group(account, security_group)
        diffs.append(diff)

    if args.update_sg:
        store.save()
        output = {
            "schema": "cloudmapper.reachability/v1+incremental-diff",
            "state": args.state,
            "updates": diffs,
        }
        text = json.dumps(output, indent=2, sort_keys=True, default=list)
        print(text)
        if args.out:
            with open(args.out, "w") as handle:
                handle.write(text + "\n")
        return 0

    reports = [store.analyze(name) for name in names]
    combined = {
        "schema": "cloudmapper.reachability/v1+collection",
        "source": INTERNET_CIDR,
        "state": args.state,
        "accounts": reports,
        "paths": [path for report in reports for path in report.paths],
    }
    _emit(combined, args)
    _maybe_write_overlay(combined, args)
    if args.check and any(report.summary["paths"] for report in reports):
        return 1
    return 0


def _emit(report, args):
    if args.format == "json":
        output = render_json(report)
    elif args.format == "markdown":
        output = render_markdown(report)
    else:
        output = render_text(report)
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(output)
    else:
        print(output)


def _maybe_write_overlay(report, args):
    if not args.web_overlay:
        return
    path = args.web_overlay
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, default=list)


def _exit_code(report, args):
    if args.check and report.get("summary", {}).get("paths"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
