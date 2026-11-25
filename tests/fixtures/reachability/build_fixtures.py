#!/usr/bin/env python
"""Materialize the three acceptance account fixtures.

Outputs, per account directory:
* ``topology.json``          normalized topology + SG rules
* ``graph.json``             Cytoscape graph in ``prepare`` format
* ``expected_paths.json``    hand-derived oracle
* ``manual_reasoning.md``    human readable reasoning
* ``us-east-1/*.json``       raw CloudMapper/AWS style snapshot files
"""
from __future__ import absolute_import, print_function

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared.reachability import (  # noqa: E402
    Topology,
    model_from_topology,
    ReachabilityAnalyzer,
)
from tests.fixtures.reachability.fixtures import (  # noqa: E402
    ACCOUNTS,
    INCREMENTAL_SCENARIOS,
    MANUAL_EXPECTATIONS,
)


def topology_from_account(account):
    topology = Topology(name=account["name"], account_id=account["account_id"])
    for resource in account["resources"]:
        topology.add_resource(resource)
    topology.set_security_groups(account["security_groups"])
    topology.classify_sensitive()
    return topology


def _aws_node_data(resource):
    rtype = resource["type"]
    sg_ids = resource.get("sg_ids", [])
    if rtype == "ec2":
        data = {
            "InstanceId": resource["id"],
            "PrivateIpAddress": (resource.get("private_ips") or [None])[0],
            "SecurityGroups": [{"GroupId": sg_id} for sg_id in sg_ids],
            "Tags": [{"Key": "Name", "Value": resource.get("name", resource["id"])}],
        }
        if resource.get("public_ips"):
            data["PublicIpAddress"] = resource["public_ips"][0]
        return data
    if rtype == "elbv2":
        return {
            "LoadBalancerName": resource["id"],
            "Scheme": "internet-facing" if resource.get("internet_reachable") else "internal",
            "SecurityGroups": sg_ids,
        }
    if rtype == "rds":
        return {
            "DBInstanceIdentifier": resource["id"],
            "PubliclyAccessible": bool(resource.get("internet_reachable")),
            "VpcSecurityGroups": [{"VpcSecurityGroupId": sg_id} for sg_id in sg_ids],
        }
    if rtype == "redshift":
        return {
            "ClusterIdentifier": resource["id"],
            "PubliclyAccessible": bool(resource.get("internet_reachable")),
            "VpcSecurityGroups": [{"VpcSecurityGroupId": sg_id} for sg_id in sg_ids],
        }
    if rtype == "elasticsearch":
        return {
            "DomainName": resource["id"],
            "VPCOptions": {"SecurityGroupIds": sg_ids},
        }
    return {"Name": resource.get("name", resource["id"]), "SecurityGroups": sg_ids}


def build_cytoscape(account):
    topology = topology_from_account(account)
    model = model_from_topology(topology)
    elements = []
    for resource in account["resources"]:
        elements.append(
            {
                "data": {
                    "id": resource["id"],
                    "name": resource.get("name", resource["id"]),
                    "type": resource["type"],
                    "local_id": resource["id"],
                    "node_data": _aws_node_data(resource),
                }
            }
        )

    raw_sgs = {sg["GroupId"]: sg for sg in account["security_groups"]}
    for source_id in sorted(model.adjacency):
        for target_id in sorted(model.adjacency[source_id]):
            if source_id == target_id:
                continue
            openings = model.adjacency[source_id][target_id]
            reason_sg_ids = []
            for opening in openings:
                sg_id = opening.get("sg_id")
                if sg_id and sg_id not in reason_sg_ids:
                    reason_sg_ids.append(sg_id)
            reasons = [raw_sgs[sg_id] for sg_id in reason_sg_ids if sg_id in raw_sgs]
            elements.append(
                {
                    "data": {
                        "source": source_id,
                        "target": target_id,
                        "type": "edge",
                        "node_data": reasons,
                    }
                }
            )
    return elements


def build_raw_snapshot(account, directory):
    region_dir = os.path.join(directory, "us-east-1")
    os.makedirs(region_dir, exist_ok=True)
    _write(
        os.path.join(region_dir, "ec2-describe-security-groups.json"),
        {"SecurityGroups": account["security_groups"]},
    )

    instances = []
    for resource in account["resources"]:
        if resource["type"] != "ec2":
            continue
        instance = {
            "InstanceId": resource["id"],
            "PrivateIpAddress": (resource.get("private_ips") or [None])[0],
            "SecurityGroups": [
                {"GroupId": sg_id, "GroupName": sg_id}
                for sg_id in resource.get("sg_ids", [])
            ],
            "Tags": [{"Key": "Name", "Value": resource.get("name", resource["id"])}],
            "State": {"Name": "running"},
        }
        if resource.get("public_ips"):
            instance["PublicIpAddress"] = resource["public_ips"][0]
        instances.append(instance)
    if instances:
        _write(
            os.path.join(region_dir, "ec2-describe-instances.json"),
            {"Reservations": [{"Instances": instances}]},
        )

    elbv2 = [
        _aws_node_data(resource)
        for resource in account["resources"]
        if resource["type"] == "elbv2"
    ]
    if elbv2:
        _write(
            os.path.join(region_dir, "elbv2-describe-load-balancers.json"),
            {"LoadBalancers": elbv2},
        )

    rds = [
        _aws_node_data(resource)
        for resource in account["resources"]
        if resource["type"] == "rds"
    ]
    if rds:
        _write(
            os.path.join(region_dir, "rds-describe-db-instances.json"),
            {"DBInstances": rds},
        )

    redshift = [
        _aws_node_data(resource)
        for resource in account["resources"]
        if resource["type"] == "redshift"
    ]
    if redshift:
        _write(
            os.path.join(region_dir, "redshift-describe-clusters.json"),
            {"Clusters": redshift},
        )


def build_manual_markdown(account, expectation):
    lines = [
        "# Manual reasoning - {} (`{}`)".format(account["title"], account["account_id"]),
        "",
    ]
    for paragraph in account["narrative"]:
        lines.append("- " + paragraph)
    lines.append("")
    lines.append("## Expected internet -> sensitive paths")
    lines.append("")
    if expectation["paths"]:
        lines.append("| # | Path | Hop ports |")
        lines.append("| - | ---- | --------- |")
        for index, path in enumerate(expectation["paths"], 1):
            lines.append(
                "| {} | `{}` | `{}` |".format(
                    index,
                    " -> ".join(path["nodes"]),
                    ", ".join(path["hop_ports"]),
                )
            )
    else:
        lines.append("No reachable sensitive paths.")
    lines.append("")
    lines.append(
        "Reachable sensitive resources: `{}`".format(
            ", ".join(expectation["reachable_sensitive_resources"]) or "(none)"
        )
    )
    lines.append(
        "Unreachable sensitive resources: `{}`".format(
            ", ".join(expectation["unreachable_sensitive_resources"]) or "(none)"
        )
    )
    lines.append("")
    lines.append("## Incremental rule changes")
    lines.append("")
    for key, scenario in INCREMENTAL_SCENARIOS.items():
        if scenario.get("account", key) != account["name"] and key != account["name"]:
            continue
        lines.append("### `{}`".format(key))
        lines.append("")
        lines.append(scenario["description"])
        lines.append("")
        for path in scenario.get("added", []):
            lines.append("- adds `{}`".format(" -> ".join(path)))
        for path in scenario.get("removed", []):
            lines.append("- removes `{}`".format(" -> ".join(path)))
        for path in scenario.get("remaining", []):
            lines.append("- keeps `{}`".format(" -> ".join(path)))
        lines.append("")
    return "\n".join(lines)


def _write(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(payload, str):
        with open(path, "w") as handle:
            handle.write(payload)
    else:
        with open(path, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")


def build_all(root=None):
    root = root or os.path.join(HERE, "accounts")
    written = []
    for account in ACCOUNTS:
        directory = os.path.join(root, account["name"])
        os.makedirs(directory, exist_ok=True)
        expectation = MANUAL_EXPECTATIONS[account["name"]]

        _write(os.path.join(directory, "topology.json"), account)
        _write(os.path.join(directory, "graph.json"), build_cytoscape(account))
        _write(os.path.join(directory, "expected_paths.json"), expectation)
        _write(
            os.path.join(directory, "manual_reasoning.md"),
            build_manual_markdown(account, expectation),
        )
        build_raw_snapshot(account, directory)
        written.append(directory)
    return written


def build_web_bundle(output_path=None):
    """Bundle the three account graphs + reports for web/reachability.html."""
    output_path = output_path or os.path.join(
        REPO_ROOT, "web", "reachability-demo.json"
    )
    bundle = {"schema": "cloudmapper.reachability/v1+bundle", "accounts": []}
    analyzer = ReachabilityAnalyzer()
    for account in ACCOUNTS:
        graph = build_cytoscape(account)
        report = analyzer.analyze(graph, name=account["name"])
        bundle["accounts"].append(
            {
                "name": account["name"],
                "title": account["title"],
                "graph": graph,
                "report": json.loads(json.dumps(report, default=list)),
            }
        )
    _write(output_path, bundle)
    return output_path


if __name__ == "__main__":
    for directory in build_all():
        print("wrote", os.path.relpath(directory, REPO_ROOT))
    if "--web" in sys.argv:
        path = build_web_bundle()
        print("wrote", os.path.relpath(path, REPO_ROOT))
