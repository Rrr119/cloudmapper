#!/usr/bin/env python
"""Human-readable acceptance check.

Verifies, for the three accounts, that engine paths exactly match the
hand-derived oracle, then replays every incremental rule-change scenario and
checks the path diff.  Exits non-zero on the first mismatch.
"""
from __future__ import absolute_import, print_function

import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared.reachability import (  # noqa: E402
    IncrementalReachability,
    ReachabilityAnalyzer,
)
from tests.fixtures.reachability.fixtures import (  # noqa: E402
    ACCOUNTS,
    INCREMENTAL_SCENARIOS,
    MANUAL_EXPECTATIONS,
)


def short(path):
    return " -> ".join(node.replace("0.0.0.0/0", "internet") for node in path)


def main():
    failures = []
    print("=" * 78)
    print("PART 1 - three accounts: engine paths vs manual reasoning")
    print("=" * 78)
    for account in ACCOUNTS:
        name = account["name"]
        expected = MANUAL_EXPECTATIONS[name]
        report = ReachabilityAnalyzer().analyze(copy.deepcopy(account), name=name)
        got = [list(p.nodes) for p in report.paths]
        want = [list(p["nodes"]) for p in expected["paths"]]
        match = got == want
        print("\n[{}] {} ({})".format("PASS" if match else "FAIL", name, account["account_id"]))
        print("  sensitive: {}".format(", ".join(r["id"] for r in report.sensitive_resources)))
        for path in report.paths:
            print("    PATH {}".format(short(path.nodes)))
            print(
                "         ports: {}".format(
                    " | ".join("{}:{}".format(h.source, h.port) for h in path.hops)
                )
            )
        if not match:
            failures.append(name)
            print("  expected:")
            for path in want:
                print("    WANT {}".format(short(path)))
            print("  got:")
            for path in got:
                print("    GOT  {}".format(short(path)))
        else:
            print("  => matches {} manually derived path(s)".format(len(want)))

    print("\n" + "=" * 78)
    print("PART 2 - incremental security-group rule changes")
    print("=" * 78)
    store = IncrementalReachability()
    for account in ACCOUNTS:
        store.add_account(account["name"], copy.deepcopy(account))

    for key, scenario in INCREMENTAL_SCENARIOS.items():
        account_name = scenario.get("account", key)
        diff = store.update_security_group(account_name, copy.deepcopy(scenario["sg_change"]))
        added = sorted(tuple(p) for p in diff.added_path_keys)
        removed = sorted(tuple(p) for p in diff.removed_path_keys)
        want_added = sorted(tuple(p) for p in scenario["added"])
        want_removed = sorted(tuple(p) for p in scenario["removed"])
        remaining = sorted(tuple(p) for p in diff.report.path_keys)
        want_remaining = sorted(tuple(p) for p in scenario["remaining"])
        match = (
            added == want_added
            and removed == want_removed
            and remaining == want_remaining
        )
        print("\n[{}] {} ({})".format("PASS" if match else "FAIL", key, account_name))
        print("  {}".format(scenario["description"]))
        print("  changed SGs: {}".format(", ".join(diff.changed_security_groups)))
        print("  + {} path(s), - {} path(s), {} unchanged".format(
            diff.paths_added_count, diff.paths_removed_count, diff.paths_unchanged
        ))
        if not match:
            failures.append(key)
            print("    added    got={}".format(added))
            print("    added   want={}".format(want_added))
            print("    removed  got={}".format(removed))
            print("    removed want={}".format(want_removed))
            print("    remain   got={}".format(remaining))
            print("    remain  want={}".format(want_remaining))

    # Account isolation check on a dedicated untouched store.
    iso = IncrementalReachability()
    for account in ACCOUNTS:
        iso.add_account(account["name"], copy.deepcopy(account))
    analytics_before = iso.cached_report("analytics")["path_keys"]
    partner_before = iso.cached_report("partner")["path_keys"]
    iso.update_security_group("shop", copy.deepcopy(INCREMENTAL_SCENARIOS["shop"]["sg_change"]))
    isolated = (
        iso.cached_report("analytics")["path_keys"] == analytics_before
        and iso.cached_report("partner")["path_keys"] == partner_before
    )
    print("\n[{}] rule change in shop does not invalidate other accounts".format(
        "PASS" if isolated else "FAIL"
    ))
    if not isolated:
        failures.append("account-isolation")

    print("\n" + "=" * 78)
    if failures:
        print("ACCEPTANCE FAILED: {}".format(", ".join(failures)))
        return 1
    print("ACCEPTANCE PASSED: 3 accounts match manual reasoning; incremental diffs correct.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
