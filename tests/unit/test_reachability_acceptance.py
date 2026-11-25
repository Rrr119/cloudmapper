# -*- coding: utf-8 -*-
"""Acceptance tests: three accounts vs manual reasoning + incremental updates.

These tests are intentionally stdlib/unittest only so they can run in a
minimal environment via ``python -m unittest tests.unit.test_reachability_acceptance``.
"""
from __future__ import absolute_import

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared.reachability import (  # noqa: E402
    INTERNET_CIDR,
    IncrementalReachability,
    ReachabilityAnalyzer,
    topology_from_account_data,
    topology_from_spec,
)
from tests.fixtures.reachability.fixtures import (  # noqa: E402
    ACCOUNTS,
    INCREMENTAL_SCENARIOS,
    MANUAL_EXPECTATIONS,
    account_by_name,
)

FIXTURE_ROOT = os.path.join(
    REPO_ROOT, "tests", "fixtures", "reachability", "accounts"
)


def nodes(report):
    return [list(path["nodes"]) for path in report["paths"]]


def expected_nodes(account_name):
    return [list(path["nodes"]) for path in MANUAL_EXPECTATIONS[account_name]["paths"]]


class ThreeAccountAcceptanceTest(unittest.TestCase):
    """The headline acceptance criterion for all three accounts."""

    def test_manual_oracle_matches_for_all_accounts(self):
        for account in ACCOUNTS:
            name = account["name"]
            expectation = MANUAL_EXPECTATIONS[name]
            report = ReachabilityAnalyzer().analyze(copy.deepcopy(account), name=name)

            self.assertEqual(
                sorted(expectation["sensitive_resources"]),
                sorted(r["id"] for r in report["sensitive_resources"]),
                msg="sensitive classification mismatch in {}".format(name),
            )
            self.assertEqual(
                expected_nodes(name),
                nodes(report),
                msg="path mismatch in account {}".format(name),
            )
            self.assertEqual(
                sorted(expectation["reachable_sensitive_resources"]),
                sorted(report["reachable_resources"]),
                msg="reachable set mismatch in {}".format(name),
            )
            for unreachable in expectation["unreachable_sensitive_resources"]:
                self.assertNotIn(unreachable, report["reachable_resources"])

    def test_hop_ports_match_manual_oracle(self):
        for account in ACCOUNTS:
            name = account["name"]
            expectation = MANUAL_EXPECTATIONS[name]
            report = ReachabilityAnalyzer().analyze(copy.deepcopy(account), name=name)
            self.assertEqual(len(report.paths), len(expectation["paths"]))
            for path, expected in zip(report.paths, expectation["paths"]):
                self.assertEqual(list(path.nodes), expected["nodes"])
                self.assertEqual(len(path.hops), len(expected["hop_ports"]))
                for hop, expected_port in zip(path.hops, expected["hop_ports"]):
                    offered_ports = {opening["port"] for opening in hop["openings"]}
                    self.assertIn(
                        expected_port,
                        offered_ports,
                        msg="{} hop {} ports {}".format(name, hop.hop, offered_ports),
                    )

    def test_topology_json_files_on_disk(self):
        for name in MANUAL_EXPECTATIONS:
            path = os.path.join(FIXTURE_ROOT, name, "topology.json")
            report = ReachabilityAnalyzer().analyze(path)
            self.assertEqual(expected_nodes(name), nodes(report), msg=name)

    def test_existing_graph_data_compatibility(self):
        """graph.json uses the prepare.py Cytoscape element/edge shape."""
        for name in MANUAL_EXPECTATIONS:
            graph_path = os.path.join(FIXTURE_ROOT, name, "graph.json")
            with open(graph_path) as handle:
                graph = json.load(handle)
            # Every element must use the established {"data": {...}} envelope.
            self.assertTrue(all("data" in element for element in graph))
            edge = next(
                element
                for element in graph
                if element["data"].get("type") == "edge"
            )
            self.assertIn("source", edge["data"])
            self.assertIn("target", edge["data"])

            report = ReachabilityAnalyzer().analyze(graph_path, name=name)
            self.assertEqual(
                expected_nodes(name),
                nodes(report),
                msg="graph adapter mismatch in {}".format(name),
            )
            self.assertGreaterEqual(report.summary["verified_paths"], 1)

    def test_raw_account_data_snapshot_loader(self):
        # The raw snapshot loader covers the two EC2/RDS/Redshift accounts.
        for name in ("shop", "analytics"):
            topology = topology_from_account_data(
                os.path.join(FIXTURE_ROOT, name), use_topology_spec=False
            )
            report = ReachabilityAnalyzer().analyze(topology, name=name)
            self.assertEqual(expected_nodes(name), nodes(report), msg=name)

    def test_private_only_instance_is_not_an_entry_point(self):
        topology = topology_from_spec(copy.deepcopy(account_by_name("partner")))
        adjacency = topology.adjacency()
        self.assertNotIn("hidden", adjacency.get(INTERNET_CIDR, {}))

        graph_report = ReachabilityAnalyzer().analyze(
            os.path.join(FIXTURE_ROOT, "partner", "graph.json")
        )
        for path in graph_report.paths:
            self.assertNotIn("hidden", path.nodes)


class PortAndProtocolQueryTest(unittest.TestCase):
    def test_destination_port_filters_final_hop(self):
        report = ReachabilityAnalyzer(port=5432).analyze(
            copy.deepcopy(account_by_name("shop"))
        )
        self.assertEqual(
            expected_nodes("shop"),
            nodes(report),
            "Both chains terminate at PostgreSQL/5432",
        )

        https = ReachabilityAnalyzer(port=443).analyze(
            os.path.join(FIXTURE_ROOT, "partner", "graph.json")
        )
        self.assertEqual(
            [[INTERNET_CIDR, "elb-partner", "api", "es-partner"]],
            nodes(https),
        )

        mysql = ReachabilityAnalyzer(port=3306).analyze(
            os.path.join(FIXTURE_ROOT, "partner", "graph.json")
        )
        self.assertEqual([[INTERNET_CIDR, "rds-leak"]], nodes(mysql))

    def test_explicit_intermediate_target(self):
        report = ReachabilityAnalyzer(port=22, sensitive_ids={"app"}).analyze(
            copy.deepcopy(account_by_name("shop"))
        )
        self.assertEqual(
            [[INTERNET_CIDR, "bastion", "app"]],
            nodes(report),
        )


class IncrementalUpdateTest(unittest.TestCase):
    def setUp(self):
        self.store = IncrementalReachability()
        for account in ACCOUNTS:
            self.store.add_account(
                account["name"], topology=topology_from_spec(copy.deepcopy(account))
            )

    def test_shop_rule_revocation_is_incremental(self):
        scenario = INCREMENTAL_SCENARIOS["shop"]
        diff = self.store.update_security_group("shop", scenario["sg_change"])

        self.assertTrue(diff.changed)
        self.assertTrue(diff.incremental)
        self.assertEqual(["sg-shop-web"], diff.changed_security_groups)
        self.assertEqual(
            [list(path) for path in scenario["removed"]], diff.removed_path_keys
        )
        self.assertEqual([], diff.added_path_keys)
        current = [list(key) for key in diff.report.path_keys]
        self.assertEqual([list(path) for path in scenario["remaining"]], current)
        # The internet -> web edge itself must disappear.
        self.assertIn("{} -> web".format(INTERNET_CIDR), diff.edges_removed)

    def test_analytics_add_then_lock(self):
        add_scenario = INCREMENTAL_SCENARIOS["analytics_add_trust"]
        diff = self.store.update_security_group(
            "analytics", add_scenario["sg_change"]
        )
        self.assertEqual(
            sorted(list(path) for path in add_scenario["added"]),
            sorted(diff.added_path_keys),
        )
        self.assertEqual([], diff.removed_path_keys)
        self.assertEqual(4, diff.report.summary["paths"])

        lock_scenario = INCREMENTAL_SCENARIOS["analytics_lock_jump"]
        locked = self.store.update_security_group(
            "analytics", lock_scenario["sg_change"]
        )
        self.assertEqual(
            sorted(list(path) for path in lock_scenario["removed"]),
            sorted(locked.removed_path_keys),
        )
        self.assertEqual([], locked.report.path_keys)

    def test_noop_update(self):
        original_sg = account_by_name("shop")["security_groups"][0]
        diff = self.store.update_security_group("shop", copy.deepcopy(original_sg))
        self.assertFalse(diff.changed)
        self.assertEqual([], diff.paths_added)
        self.assertEqual([], diff.paths_removed)

    def test_account_isolation(self):
        analytics_before = self.store.cached_report("analytics")["path_keys"]
        partner_before = self.store.cached_report("partner")["path_keys"]

        self.store.update_security_group(
            "shop", INCREMENTAL_SCENARIOS["shop"]["sg_change"]
        )

        self.assertEqual(
            analytics_before, self.store.cached_report("analytics")["path_keys"]
        )
        self.assertEqual(
            partner_before, self.store.cached_report("partner")["path_keys"]
        )

    def test_persistence_across_processes(self):
        temp_dir = tempfile.mkdtemp(prefix="reachability-state-")
        try:
            state_path = os.path.join(temp_dir, "state.json")
            self.store.save(state_path)
            self.assertTrue(os.path.isfile(state_path))

            reopened = IncrementalReachability(state_path=state_path)
            self.assertEqual(
                self.store.cached_report("shop")["path_keys"],
                reopened.cached_report("shop")["path_keys"],
            )
            diff = reopened.update_security_group(
                "shop", INCREMENTAL_SCENARIOS["shop"]["sg_change"]
            )
            self.assertEqual(1, diff.paths_removed_count)
            reopened.save()

            reloaded = IncrementalReachability(state_path=state_path)
            self.assertEqual(
                [list(INCREMENTAL_SCENARIOS["shop"]["remaining"][0])],
                reloaded.cached_report("shop")["path_keys"],
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_refresh_from_changed_files(self):
        temp_dir = tempfile.mkdtemp(prefix="reachability-files-")
        try:
            shop_dir = os.path.join(temp_dir, "shop")
            shutil.copytree(os.path.join(FIXTURE_ROOT, "shop"), shop_dir)
            store = IncrementalReachability()
            store.add_account_from_directory("shop", shop_dir)

            spec_path = os.path.join(shop_dir, "topology.json")
            with open(spec_path) as handle:
                spec = json.load(handle)
            for index, sg in enumerate(spec["security_groups"]):
                if sg["GroupId"] == "sg-shop-web":
                    spec["security_groups"][index] = INCREMENTAL_SCENARIOS["shop"][
                        "sg_change"
                    ]
            with open(spec_path, "w") as handle:
                json.dump(spec, handle)

            result = store.refresh_from_directory("shop", shop_dir)
            self.assertIn("sg-shop-web", result["changed_security_groups"])
            final = store.cached_report("shop")
            self.assertEqual(
                [list(path) for path in INCREMENTAL_SCENARIOS["shop"]["remaining"]],
                final["path_keys"],
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class DemoGraphSmokeTest(unittest.TestCase):
    """If prepare.py has been run against the bundled demo account."""

    def test_demo_data_json_is_analysable(self):
        graph_path = os.path.join(REPO_ROOT, "web", "data.json")
        if not os.path.isfile(graph_path):
            self.skipTest("web/data.json not generated by prepare")
        report = ReachabilityAnalyzer().analyze(graph_path, name="demo")
        self.assertIn("paths", report)
        self.assertGreater(report.summary["edges"], 0)


class SimplifiedRuleFormatTest(unittest.TestCase):
    def test_simplified_rules_and_aliases(self):
        from shared.reachability import get_reachable_paths

        spec = {
            "name": "synthetic",
            "security_groups": [
                {
                    "GroupId": "sg-a",
                    "ingress_rules": [
                        {"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"}
                    ],
                },
                {
                    "GroupId": "sg-db",
                    "rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 5432,
                            "to_port": 5432,
                            "source_security_group": "sg-a",
                        }
                    ],
                },
            ],
            "resources": [
                {
                    "id": "web",
                    "type": "ec2",
                    "security_groups": ["sg-a"],
                    "public_ip": "54.0.0.1",
                    "public": True,
                },
                {
                    "id": "db",
                    "type": "rds",
                    "security_group_ids": ["sg-db"],
                    "private_ips": ["10.0.0.5"],
                },
            ],
        }
        paths = get_reachable_paths(spec)
        self.assertEqual(
            [[INTERNET_CIDR, "web", "db"]], [list(p["nodes"]) for p in paths]
        )
        self.assertIn("path", paths[0])
        self.assertEqual(paths[0]["path"], paths[0]["nodes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
