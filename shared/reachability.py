"""Internet -> sensitive resource reachability analysis.

This module adds path based reachability analysis to CloudMapper.  It reasons
about EC2 security group rules (CIDR and source-security-group based rules)
and can consume either:

1. The Cytoscape graph JSON produced by ``cloudmapper prepare``
   (a list of ``{"data": {...}}`` elements, usually ``web/data.json``), or
2. A normalized topology document / raw ``account-data/<account>`` snapshot
   containing ``ec2-describe-security-groups.json`` and resource inventories.

The implementation only depends on the Python standard library so it can be
imported and unit tested in minimal environments.
"""
from __future__ import print_function

import copy
import hashlib
import ipaddress
import json
import os
import re
from collections import OrderedDict, defaultdict


SCHEMA_VERSION = "cloudmapper.reachability/v1"

INTERNET_CIDR = "0.0.0.0/0"
INTERNET_V6_CIDR = "::/0"
INTERNET_SOURCES = (INTERNET_CIDR, INTERNET_V6_CIDR)
INTERNET_NAME = "Public Internet"

# Resource types that are considered sensitive data stores by default.
SENSITIVE_TYPES = {
    "rds",
    "rds_rr",
    "redshift",
    "elasticsearch",
    "es",
    "opensearch",
    "elasticache",
    "docdb",
    "neptune",
    "memorydb",
    "database",
    "db",
}

SENSITIVE_NAME_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(^|[-_])db([-_]|$)",
        r"database",
        r"mysql",
        r"postgres(ql)?",
        r"mariadb",
        r"oracle",
        r"sqlserver",
        r"mongo",
        r"redshift",
        r"elastic(search)?",
        r"opensearch",
        r"secrets?[-_]",
        r"vault",
        r"sensitive",
        r"pii",
        r"payment",
        r"cardholder",
        r"prod[-_]?data",
    )
]


class AttrDict(dict):
    """Dictionary with attribute access for convenient use from tests/CLI."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


# ---------------------------------------------------------------------------
# CIDR / port helpers
# ---------------------------------------------------------------------------

def normalize_protocol(protocol):
    """Normalize AWS IpProtocol values to tcp/udp/icmp/all."""
    if protocol is None:
        return None
    protocol = str(protocol).lower()
    if protocol in ("-1", "all", "*"):
        return "all"
    numeric = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
    return numeric.get(protocol, protocol)


def ip_matches_cidr(ip_address, cidr):
    try:
        return ipaddress.ip_address(str(ip_address)) in ipaddress.ip_network(
            str(cidr), strict=False
        )
    except (ValueError, TypeError):
        return False


def cidrs_related(left, right):
    """Return True when two CIDRs are equal or one contains the other."""
    if left == right:
        return True
    try:
        left_net = ipaddress.ip_network(str(left), strict=False)
        right_net = ipaddress.ip_network(str(right), strict=False)
    except (ValueError, TypeError):
        return False
    if left_net.version != right_net.version:
        return False

    def spans(inner, outer):
        return (
            int(inner.network_address) >= int(outer.network_address)
            and int(inner.broadcast_address) <= int(outer.broadcast_address)
        )

    return spans(left_net, right_net) or spans(right_net, left_net)


def port_allowed(port, from_port, to_port):
    if port is None:
        return True
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False
    if from_port is None or to_port is None:
        return True
    try:
        low, high = int(from_port), int(to_port)
    except (TypeError, ValueError):
        return True
    if low == -1 or high == -1:
        # AWS uses -1 as a wildcard in some ICMP / all-traffic documents.
        return True
    return low <= port <= high


def format_port_range(protocol, from_port, to_port):
    protocol = normalize_protocol(protocol)
    if protocol == "all" or (from_port is None and to_port is None):
        return "all"
    if from_port in (None, -1) and to_port in (None, -1):
        return "all"
    start = from_port if from_port not in (None, -1) else 0
    end = to_port if to_port not in (None, -1) else 65535
    if start == end:
        return "{}/{}".format(start, protocol or "?")
    return "{}-{}/{}".format(start, end, protocol or "?")


# ---------------------------------------------------------------------------
# Security group rule parsing
# ---------------------------------------------------------------------------

def parse_security_group(security_group):
    """Return normalized ingress permissions for an AWS security group dict."""
    group_id = security_group.get("GroupId") or security_group.get("id")
    group_name = security_group.get("GroupName") or security_group.get("name")
    permissions = []
    raw_permissions = list(security_group.get("IpPermissions", []) or [])
    # Tolerate simplified / synthetic rule documents.
    for key in ("ingress", "ingress_rules", "rules", "Rules"):
        if security_group.get(key):
            raw_permissions.extend(security_group[key])
    for raw_permission in raw_permissions:
        raw_permission = _normalize_permission_keys(raw_permission)
        protocol = normalize_protocol(raw_permission.get("IpProtocol"))
        from_port = raw_permission.get("FromPort")
        to_port = raw_permission.get("ToPort")
        if protocol == "all":
            # AWS omits port ranges for all-protocol rules.
            from_port = None
            to_port = None
        cidrs = []
        for ip_range in raw_permission.get("IpRanges", []) or []:
            cidr = ip_range.get("CidrIp") if isinstance(ip_range, dict) else ip_range
            if cidr:
                cidrs.append(cidr)
        ipv6_cidrs = []
        for ip_range in raw_permission.get("Ipv6Ranges", []) or []:
            cidr = (
                ip_range.get("CidrIpv6") if isinstance(ip_range, dict) else ip_range
            )
            if cidr:
                ipv6_cidrs.append(cidr)
        source_sgs = []
        pairs = []
        for pair in raw_permission.get("UserIdGroupPairs", []) or []:
            if isinstance(pair, dict) and pair.get("GroupId"):
                source_sgs.append(pair["GroupId"])
                pairs.append(
                    {
                        "group_id": pair["GroupId"],
                        "user_id": pair.get("UserId"),
                        "vpc_id": pair.get("VpcId"),
                    }
                )
        prefix_lists = []
        for prefix in raw_permission.get("PrefixListIds", []) or []:
            prefix_id = (
                prefix.get("PrefixListId") if isinstance(prefix, dict) else prefix
            )
            if prefix_id:
                prefix_lists.append(prefix_id)
        permissions.append(
            AttrDict(
                sg_id=group_id,
                sg_name=group_name,
                protocol=protocol,
                from_port=from_port,
                to_port=to_port,
                cidrs=cidrs,
                ipv6_cidrs=ipv6_cidrs,
                all_cidrs=cidrs + ipv6_cidrs,
                source_sgs=source_sgs,
                pairs=pairs,
                prefix_list_ids=prefix_lists,
            )
        )
    return permissions


def _normalize_permission_keys(rule):
    """Map common simplified rule keys onto the AWS IpPermission shape."""
    if not isinstance(rule, dict):
        return rule
    rule = dict(rule)
    if "IpProtocol" not in rule:
        rule["IpProtocol"] = rule.get("protocol", "tcp")
    if "FromPort" not in rule:
        if rule.get("from_port") is not None:
            rule["FromPort"] = rule["from_port"]
        elif rule.get("port") is not None:
            port = rule["port"]
            if isinstance(port, str) and "-" in port:
                start, end = port.split("-", 1)
                rule["FromPort"], rule["ToPort"] = int(start), int(end)
            else:
                rule["FromPort"] = port
    if "ToPort" not in rule:
        rule["ToPort"] = rule.get("to_port", rule.get("FromPort"))
    if not rule.get("IpRanges"):
        cidrs = []
        for key in ("cidr", "CidrIp", "source_cidr"):
            if rule.get(key):
                cidrs.append(rule[key])
        for key in ("cidrs", "source_cidrs", "IpRanges"):
            value = rule.get(key)
            if isinstance(value, list):
                cidrs.extend(value)
        if cidrs:
            rule["IpRanges"] = [
                {"CidrIp": cidr} if isinstance(cidr, str) else cidr for cidr in cidrs
            ]
    if not rule.get("UserIdGroupPairs"):
        source_sgs = []
        for key in (
            "source_security_group",
            "source_sg",
            "source_security_group_id",
        ):
            if rule.get(key):
                source_sgs.append(rule[key])
        for key in ("source_security_groups", "source_sg_ids"):
            value = rule.get(key)
            if isinstance(value, list):
                source_sgs.extend(value)
        if source_sgs:
            rule["UserIdGroupPairs"] = [{"GroupId": sg_id} for sg_id in source_sgs]
    return rule


def permission_allows(
    permission, protocol=None, port=None, source_sg_ids=None, source_ip=None
):
    """Check protocol/port/source conditions on one normalized permission."""
    if protocol is not None:
        wanted = normalize_protocol(protocol)
        if permission.protocol != "all" and wanted not in (
            None,
            permission.protocol,
        ):
            return False
    if not port_allowed(port, permission.from_port, permission.to_port):
        return False

    source_sg_ids = set(source_sg_ids or [])
    if source_sg_ids and source_sg_ids.intersection(permission.source_sgs):
        return True
    if source_ip is not None:
        for cidr in permission.all_cidrs:
            if ip_matches_cidr(source_ip, cidr):
                return True
    return False


def permission_allows_internet(permission, protocol=None, port=None):
    if protocol is not None:
        wanted = normalize_protocol(protocol)
        if permission.protocol != "all" and wanted != permission.protocol:
            return False
    if not port_allowed(port, permission.from_port, permission.to_port):
        return False
    return any(cidr in INTERNET_SOURCES for cidr in permission.all_cidrs)


def sg_fingerprint(security_group):
    """Stable fingerprint used by the incremental update machinery."""
    canonical = json.dumps(security_group, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Sensitivity classification
# ---------------------------------------------------------------------------

def is_sensitive_resource(resource, explicit_ids=None):
    explicit_ids = set(explicit_ids or [])
    resource_id = resource.get("id") or resource.get("arn")
    if resource_id in explicit_ids:
        return True
    if resource.get("sensitive") is True:
        return True
    rtype = (resource.get("type") or "").lower()
    if rtype in SENSITIVE_TYPES:
        return True

    tags = resource.get("tags") or {}
    if isinstance(tags, list):
        tags = {tag.get("Key"): tag.get("Value") for tag in tags if isinstance(tag, dict)}
    for key, value in tags.items():
        if str(key).lower() in ("sensitive", "confidential", "data-classification"):
            if str(value).lower() in ("true", "yes", "1", "sensitive", "confidential", "restricted"):
                return True

    name = resource.get("name") or resource.get("local_id") or resource_id or ""
    for pattern in SENSITIVE_NAME_PATTERNS:
        if pattern.search(str(name)):
            return True
    return False


# ---------------------------------------------------------------------------
# Normalized topology
# ---------------------------------------------------------------------------

class Topology(object):
    """Normalized resources + security groups for one account."""

    def __init__(self, name=None, account_id=None):
        self.name = name
        self.account_id = account_id
        self.resources = OrderedDict()
        self.security_groups = OrderedDict()
        self.rules_by_sg = OrderedDict()
        self.resources_by_sg = defaultdict(set)
        self._adjacency = None

    # -- construction -------------------------------------------------------

    def add_resource(self, resource=None, **kwargs):
        data = AttrDict(resource or {})
        data.update({k: v for k, v in kwargs.items() if v is not None})
        resource_id = data.get("id") or data.get("arn")
        if not resource_id:
            raise ValueError("resource requires an id or arn: %r" % data)
        data["id"] = resource_id
        sg_ids = list(data.get("sg_ids") or [])
        for key in ("security_groups", "security_group_ids", "SecurityGroups"):
            value = data.get(key)
            if isinstance(value, list):
                for group in value:
                    if isinstance(group, str):
                        sg_ids.append(group)
                    elif isinstance(group, dict) and (group.get("GroupId") or group.get("id")):
                        sg_ids.append(group.get("GroupId") or group.get("id"))
        data["sg_ids"] = sorted(set(sg_ids))
        data.setdefault("private_ips", [])
        data.setdefault("public_ips", [])
        if data.get("internet_reachable") is None:
            data["internet_reachable"] = bool(
                data.get("public_ips")
                or data.get("public") is True
                or data.get("is_public") is True
                or data.get("publicly_accessible") is True
            )
        data.setdefault("sensitive", None)
        data.setdefault("tags", {})
        data.setdefault("type", "unknown")
        self.resources[resource_id] = data
        for sg_id in data.sg_ids:
            self.resources_by_sg[sg_id].add(resource_id)
        return data

    def add_security_group(self, security_group):
        sg_id = security_group.get("GroupId") or security_group.get("id")
        if not sg_id:
            raise ValueError("security group requires GroupId: %r" % security_group)
        self.security_groups[sg_id] = security_group
        self.rules_by_sg[sg_id] = parse_security_group(security_group)
        return sg_id

    def set_security_groups(self, security_groups):
        self.security_groups = OrderedDict()
        self.rules_by_sg = OrderedDict()
        for sg in security_groups:
            self.add_security_group(sg)

    def classify_sensitive(self, explicit_ids=None):
        sensitive = set()
        for resource_id, resource in self.resources.items():
            if is_sensitive_resource(resource, explicit_ids):
                resource.sensitive = True
                sensitive.add(resource_id)
            else:
                resource.sensitive = False
        return sensitive

    # -- adjacency derived from rules --------------------------------------

    def _opening(self, permission, source_kind, source_value):
        return AttrDict(
            protocol=permission.protocol or "all",
            from_port=permission.from_port,
            to_port=permission.to_port,
            port=format_port_range(
                permission.protocol, permission.from_port, permission.to_port
            ),
            sg_id=permission.sg_id,
            sg_name=permission.sg_name,
            source_kind=source_kind,
            source_value=source_value,
            verified=True,
        )

    def openings_for_security_group(self, sg_id):
        """Yield ``(source_id, target_id, opening)`` triples for one SG."""
        results = []
        targets = [
            self.resources[resource_id]
            for resource_id in self.resources_by_sg.get(sg_id, set())
            if resource_id in self.resources
        ]
        for permission in self.rules_by_sg.get(sg_id, []):
            # CIDR based sources
            for cidr in permission.all_cidrs:
                if cidr in INTERNET_SOURCES:
                    for target in targets:
                        if target.internet_reachable:
                            results.append(
                                (
                                    INTERNET_CIDR,
                                    target.id,
                                    self._opening(permission, "cidr", cidr),
                                )
                            )
                    continue

                matched_source = False
                for source in self.resources.values():
                    if any(
                        ip_matches_cidr(ip, cidr) for ip in source.private_ips + source.public_ips
                    ):
                        matched_source = True
                        for target in targets:
                            results.append(
                                (
                                    source.id,
                                    target.id,
                                    self._opening(permission, "cidr", cidr),
                                )
                            )
                if not matched_source:
                    # The CIDR may describe an external/unknown network.  It is
                    # not a node we can launch a multi-hop path from, so no edge.
                    continue

            # Source security group based rules
            for source_sg in permission.source_sgs:
                for source_id in self.resources_by_sg.get(source_sg, set()):
                    source = self.resources.get(source_id)
                    if source is None:
                        continue
                    for target in targets:
                        results.append(
                            (
                                source.id,
                                target.id,
                                self._opening(
                                    permission, "security-group", source_sg
                                ),
                            )
                        )
        return results

    def adjacency(self):
        """Return ``source -> target -> [opening]`` from the SG rules.

        The result is cached and surgically updated by
        :meth:`apply_security_group_change`, which is what makes rule
        updates incremental.
        """
        if self._adjacency is not None:
            return self._adjacency
        adjacency = defaultdict(lambda: defaultdict(list))
        for sg_id in self.rules_by_sg:
            for source_id, target_id, opening in self.openings_for_security_group(sg_id):
                adjacency[source_id][target_id].append(opening)
        self._adjacency = {
            source: {target: list(openings) for target, openings in targets.items()}
            for source, targets in adjacency.items()
        }
        return self._adjacency

    def _remove_openings_for_sg(self, sg_id):
        if self._adjacency is None:
            return
        for source_id in list(self._adjacency):
            targets = self._adjacency[source_id]
            for target_id in list(targets):
                kept = [
                    opening
                    for opening in targets[target_id]
                    if opening.get("sg_id") != sg_id
                ]
                if kept:
                    targets[target_id] = kept
                else:
                    del targets[target_id]
            if not targets:
                del self._adjacency[source_id]

    def _add_openings_for_sg(self, sg_id):
        if self._adjacency is None:
            return
        for source_id, target_id, opening in self.openings_for_security_group(sg_id):
            self._adjacency.setdefault(source_id, {}).setdefault(target_id, []).append(
                opening
            )

    def apply_security_group_change(self, security_group):
        """Replace one SG and incrementally patch the cached adjacency."""
        sg_id = security_group.get("GroupId") or security_group.get("id")
        old = self.security_groups.get(sg_id)
        old_hash = sg_fingerprint(old) if old is not None else None
        new_hash = sg_fingerprint(security_group)
        changed = old_hash != new_hash
        if changed:
            self.add_security_group(security_group)
            if self._adjacency is not None:
                self._remove_openings_for_sg(sg_id)
                self._add_openings_for_sg(sg_id)
        return AttrDict(
            sg_id=sg_id,
            changed=changed,
            added=old is None,
            old_hash=old_hash,
            new_hash=new_hash,
        )

    def to_spec(self):
        return {
            "name": self.name,
            "account_id": self.account_id,
            "resources": list(self.resources.values()),
            "security_groups": list(self.security_groups.values()),
        }


def topology_from_spec(spec):
    topology = Topology(name=spec.get("name"), account_id=spec.get("account_id"))
    for resource in spec.get("resources", []):
        topology.add_resource(resource)
    topology.set_security_groups(spec.get("security_groups", []))
    topology.classify_sensitive(spec.get("sensitive_ids"))
    return topology


# ---------------------------------------------------------------------------
# Cytoscape / CloudMapper graph adapter
# ---------------------------------------------------------------------------

def _extract_sg_ids(node_type, node_data):
    sg_ids = []
    if not isinstance(node_data, dict):
        return sg_ids
    raw_groups = node_data.get("SecurityGroups")
    if isinstance(raw_groups, list):
        for group in raw_groups:
            if isinstance(group, str):
                sg_ids.append(group)
            elif isinstance(group, dict):
                sg_id = group.get("GroupId") or group.get("VpcSecurityGroupId")
                if sg_id:
                    sg_ids.append(sg_id)
    for group in node_data.get("VpcSecurityGroups", []) or []:
        if isinstance(group, dict) and group.get("VpcSecurityGroupId"):
            sg_ids.append(group["VpcSecurityGroupId"])
    vpc_options = node_data.get("VPCOptions") or {}
    for sg_id in vpc_options.get("SecurityGroupIds", []) or []:
        sg_ids.append(sg_id)
    if node_data.get("security_groups"):
        for sg_id in node_data["security_groups"]:
            if isinstance(sg_id, str):
                sg_ids.append(sg_id)
    return sorted(set(sg_ids))


def _extract_ips(node_data):
    ips = []
    if not isinstance(node_data, dict):
        return ips
    for key in ("PrivateIpAddress", "PublicIpAddress", "IpAddress"):
        if node_data.get(key):
            ips.append(node_data[key])
    for interface in node_data.get("NetworkInterfaces", []) or []:
        if not isinstance(interface, dict):
            continue
        if interface.get("PrivateIpAddress"):
            ips.append(interface["PrivateIpAddress"])
        association = interface.get("Association") or {}
        if association.get("PublicIp"):
            ips.append(association["PublicIp"])
        for private_ip in interface.get("PrivateIpAddresses", []) or []:
            if private_ip.get("PrivateIpAddress"):
                ips.append(private_ip["PrivateIpAddress"])
            assoc = private_ip.get("Association") or {}
            if assoc.get("PublicIp"):
                ips.append(assoc["PublicIp"])
    return sorted(set(ips))


def load_graph_data(source):
    """Load Cytoscape JSON from a path, JSON string, list or dict."""
    if isinstance(source, (list, dict)):
        data = source
    elif isinstance(source, str) and "\n" not in source and os.path.isfile(source):
        with open(source) as handle:
            data = json.load(handle)
    elif isinstance(source, (str, bytes)):
        data = json.loads(source)
    else:
        raise TypeError("Unsupported graph data source: %r" % type(source))
    if isinstance(data, dict) and "elements" in data:
        elements = data["elements"]
        if isinstance(elements, dict):
            elements = elements.get("nodes", []) + elements.get("edges", [])
        return elements
    return data


def _opening_from_permission(permission, source_kind, source_value, verified=True):
    return AttrDict(
        protocol=permission.protocol or "all",
        from_port=permission.from_port,
        to_port=permission.to_port,
        port=format_port_range(
            permission.protocol, permission.from_port, permission.to_port
        ),
        sg_id=permission.sg_id,
        sg_name=permission.sg_name,
        source_kind=source_kind,
        source_value=source_value,
        verified=verified,
    )


def _openings_for_edge_reasons(reasons, source_node):
    """Recover exact port openings for an edge from embedded SG objects."""
    openings = []
    if not reasons:
        # prepare.py connects unrestricted VPC endpoints with an empty reason
        # list.  The edge itself is still evidence of connectivity.
        openings.append(
            AttrDict(
                protocol="all",
                from_port=None,
                to_port=None,
                port="all",
                sg_id=None,
                sg_name=None,
                source_kind="graph-edge",
                source_value=None,
                verified=False,
            )
        )
        return openings

    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        permissions = parse_security_group(reason)
        matched_any = False
        for permission in permissions:
            kind_value = None
            # Source security group match
            matched_sgs = source_node.sg_ids.intersection(permission.source_sgs)
            if matched_sgs:
                kind_value = ("security-group", sorted(matched_sgs)[0])
            else:
                # Source IP match against CIDRs
                for ip in source_node.ips:
                    for cidr in permission.all_cidrs:
                        if ip_matches_cidr(ip, cidr):
                            kind_value = ("cidr", cidr)
                            break
                    if kind_value:
                        break
            if kind_value is None and source_node.is_cidr:
                for cidr in permission.all_cidrs:
                    if cidrs_related(source_node.id, cidr):
                        kind_value = ("cidr", cidr)
                        break
            if kind_value is None and source_node.is_internet:
                for cidr in permission.all_cidrs:
                    if cidr in INTERNET_SOURCES:
                        kind_value = ("cidr", cidr)
                        break
            if kind_value is None and source_node.is_cidr:
                # The edge source itself may be an external CIDR node whose id
                # exactly equals the rule CIDR (handled above via related()).
                continue
            if kind_value is not None:
                matched_any = True
                openings.append(
                    _opening_from_permission(permission, kind_value[0], kind_value[1])
                )
        if not matched_any:
            # CloudMapper created the edge from this SG but we could not
            # re-match the exact permission (often due to collapsed CIDRs or
            # missing node_data).  Keep the edge, mark it inferred.
            openings.append(
                AttrDict(
                    protocol="all",
                    from_port=None,
                    to_port=None,
                    port="all",
                    sg_id=reason.get("GroupId"),
                    sg_name=reason.get("GroupName"),
                    source_kind="graph-edge",
                    source_value=None,
                    verified=False,
                )
            )
    return openings


def model_from_cytoscape(source, name=None, sensitive_ids=None):
    """Build a :class:`ReachabilityModel` from prepare-style graph JSON."""
    elements = load_graph_data(source)
    model = ReachabilityModel(name=name)
    sensitive_ids = set(sensitive_ids or [])

    raw_nodes = {}
    for element in elements:
        data = element.get("data", element) if isinstance(element, dict) else {}
        if not data:
            continue
        if data.get("type") == "edge" or ("source" in data and "target" in data and "id" not in data):
            continue
        node_id = data.get("id")
        if not node_id:
            continue
        node_data = data.get("node_data") if isinstance(data.get("node_data"), dict) else {}
        node_type = data.get("type") or "unknown"
        raw_nodes[node_id] = (data, node_data, node_type)

    for node_id, (data, node_data, node_type) in raw_nodes.items():
        sg_ids = set(_extract_sg_ids(node_type, node_data))
        ips = _extract_ips(node_data)
        is_internet = node_id in INTERNET_SOURCES or (
            node_type == "cloud" and data.get("name") in (INTERNET_NAME, "Public")
        )
        is_cidr = node_type in ("ip", "cloud") or _looks_like_cidr(node_id)
        resource = AttrDict(
            id=node_id,
            arn=node_id if str(node_id).startswith("arn:") else data.get("arn"),
            name=data.get("name") or node_data.get("Name") or node_id,
            type=node_type,
            local_id=data.get("local_id"),
            sg_ids=sg_ids,
            ips=ips,
            private_ips=[ip for ip in ips if not _is_public_ip(ip)],
            public_ips=[ip for ip in ips if _is_public_ip(ip)],
            is_cidr=is_cidr,
            is_internet=is_internet,
            tags=node_data.get("Tags", []),
            raw=node_data,
        )
        resource.sensitive = is_sensitive_resource(resource, sensitive_ids)
        model.nodes[node_id] = resource
        if is_internet:
            model.internet_sources.add(node_id)

    for element in elements:
        data = element.get("data", element) if isinstance(element, dict) else {}
        if not (data.get("type") == "edge" or ("source" in data and "target" in data)):
            continue
        source_id = data.get("source")
        target_id = data.get("target")
        if not source_id or not target_id:
            continue
        source_node = model.nodes.get(source_id)
        target_node = model.nodes.get(target_id)
        if source_node is None:
            source_node = AttrDict(
                id=source_id,
                sg_ids=set(),
                ips=[],
                is_cidr=_looks_like_cidr(source_id),
                is_internet=source_id in INTERNET_SOURCES,
            )
            model.nodes[source_id] = source_node
            if source_node.is_internet:
                model.internet_sources.add(source_id)
        if target_node is None:
            target_node = AttrDict(id=target_id, sg_ids=set(), ips=[], is_cidr=False)
            model.nodes[target_id] = target_node

        reasons = data.get("node_data")
        if isinstance(reasons, dict):
            # public.py style mapping of SG id -> details; convert to list.
            reasons = [
                reason
                for reason in reasons.values()
                if isinstance(reason, dict) and "IpPermissions" in reason
            ]
        if reasons is None:
            reasons = []
        if not isinstance(reasons, list):
            reasons = [reasons]
        openings = _openings_for_edge_reasons(reasons, source_node)
        model.add_edge(source_id, target_id, openings)

    if INTERNET_CIDR not in model.internet_sources and not model.internet_sources:
        # Even when the graph omitted the unused Public node, edges may start
        # at the well known CIDR.
        if INTERNET_CIDR in model.adjacency:
            model.internet_sources.add(INTERNET_CIDR)
    return model


def _looks_like_cidr(value):
    try:
        ipaddress.ip_network(str(value), strict=False)
        return "/" in str(value)
    except (ValueError, TypeError):
        return False


def _is_public_ip(ip):
    try:
        address = ipaddress.ip_address(str(ip))
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        )
    except (ValueError, TypeError):
        return False


def model_from_topology(topology):
    """Convert a :class:`Topology` into the common traversal model."""
    model = ReachabilityModel(name=topology.name)
    sensitive = topology.classify_sensitive()
    for resource_id, resource in topology.resources.items():
        node = copy.deepcopy(resource)
        node["ips"] = list(resource.private_ips) + list(resource.public_ips)
        node["is_cidr"] = False
        node["is_internet"] = False
        node["sensitive"] = resource_id in sensitive
        model.nodes[resource_id] = node
    model.internet_sources.add(INTERNET_CIDR)
    adjacency = topology.adjacency()
    for source_id, targets in adjacency.items():
        for target_id, openings in targets.items():
            model.add_edge(source_id, target_id, openings)
    model.security_groups = topology.security_groups
    return model


class ReachabilityModel(object):
    """Common graph representation used by the path enumerator."""

    def __init__(self, name=None):
        self.name = name
        self.nodes = OrderedDict()
        self.adjacency = defaultdict(lambda: defaultdict(list))
        self.internet_sources = set()
        self.security_groups = OrderedDict()

    def add_edge(self, source_id, target_id, openings):
        existing = self.adjacency[source_id][target_id]
        for opening in openings:
            if opening not in existing:
                existing.append(opening)

    def targets(self):
        targets = set()
        for edges in self.adjacency.values():
            targets.update(edges.keys())
        return targets


# ---------------------------------------------------------------------------
# Account-data loading
# ---------------------------------------------------------------------------

def _load_json_file(path):
    with open(path) as handle:
        return json.load(handle)


def _as_list(value, key=None):
    if value is None:
        return []
    if key and isinstance(value, dict):
        value = value.get(key, [])
    return value or []


def topology_from_account_data(account_dir, name=None, use_topology_spec=True):
    """Load a raw CloudMapper account-data snapshot directory."""
    account_dir = str(account_dir)
    topology = Topology(name=name or os.path.basename(account_dir.rstrip("/")))

    topology_file = os.path.join(account_dir, "topology.json")
    if use_topology_spec and os.path.isfile(topology_file):
        spec = _load_json_file(topology_file)
        spec_topology = topology_from_spec(spec)
        spec_topology.name = topology.name
        return spec_topology

    # Security groups across every region
    sg_files = sorted(
        _glob(account_dir, "**", "ec2-describe-security-groups.json")
    ) + sorted(_glob(account_dir, "security_groups.json"))
    seen_sg = set()
    for sg_file in sg_files:
        blob = _load_json_file(sg_file)
        for sg in _as_list(blob, "SecurityGroups"):
            if sg.get("GroupId") not in seen_sg:
                seen_sg.add(sg.get("GroupId"))
                topology.add_security_group(sg)

    # EC2 instances
    for instance_file in _glob(account_dir, "**", "ec2-describe-instances.json"):
        blob = _load_json_file(instance_file)
        for reservation in _as_list(blob, "Reservations"):
            for instance in _as_list(reservation, "Instances"):
                private_ips = []
                public_ips = []
                if instance.get("PrivateIpAddress"):
                    private_ips.append(instance["PrivateIpAddress"])
                if instance.get("PublicIpAddress"):
                    public_ips.append(instance["PublicIpAddress"])
                for interface in instance.get("NetworkInterfaces", []) or []:
                    if interface.get("PrivateIpAddress"):
                        private_ips.append(interface["PrivateIpAddress"])
                    association = interface.get("Association") or {}
                    if association.get("PublicIp"):
                        public_ips.append(association["PublicIp"])
                topology.add_resource(
                    id=instance.get("InstanceId"),
                    arn=instance.get("InstanceId"),
                    name=_tag_name(instance.get("Tags")) or instance.get("InstanceId"),
                    type="ec2",
                    sg_ids=_extract_sg_ids("ec2", instance),
                    private_ips=sorted(set(private_ips)),
                    public_ips=sorted(set(public_ips)),
                    internet_reachable=bool(public_ips),
                    tags=instance.get("Tags", []),
                    raw=instance,
                )

    # Classic ELBs
    for elb_file in _glob(account_dir, "**", "elb-describe-load-balancers.json"):
        blob = _load_json_file(elb_file)
        for elb in _as_list(blob, "LoadBalancerDescriptions"):
            topology.add_resource(
                id=elb.get("LoadBalancerName"),
                name=elb.get("LoadBalancerName"),
                type="elb",
                sg_ids=elb.get("SecurityGroups", []) or [],
                internet_reachable=(elb.get("Scheme") == "internet-facing"),
                raw=elb,
            )

    # ALBs / NLBs
    for elb_file in _glob(account_dir, "**", "elbv2-describe-load-balancers.json"):
        blob = _load_json_file(elb_file)
        for elb in _as_list(blob, "LoadBalancers"):
            topology.add_resource(
                id=elb.get("LoadBalancerName") or elb.get("LoadBalancerArn"),
                arn=elb.get("LoadBalancerArn"),
                name=elb.get("LoadBalancerName"),
                type="elbv2",
                sg_ids=elb.get("SecurityGroups", []) or [],
                internet_reachable=(elb.get("Scheme") == "internet-facing"),
                raw=elb,
            )

    # RDS
    for rds_file in _glob(account_dir, "**", "rds-describe-db-instances.json"):
        blob = _load_json_file(rds_file)
        for db in _as_list(blob, "DBInstances"):
            topology.add_resource(
                id=db.get("DBInstanceIdentifier"),
                arn=db.get("DBInstanceArn"),
                name=db.get("DBInstanceIdentifier"),
                type="rds",
                sg_ids=_extract_sg_ids("rds", db),
                internet_reachable=bool(db.get("PubliclyAccessible")),
                tags=db.get("TagList", []),
                raw=db,
            )

    # Redshift
    for rs_file in _glob(account_dir, "**", "redshift-describe-clusters.json"):
        blob = _load_json_file(rs_file)
        for cluster in _as_list(blob, "Clusters"):
            topology.add_resource(
                id=cluster.get("ClusterIdentifier"),
                name=cluster.get("ClusterIdentifier"),
                type="redshift",
                sg_ids=_extract_sg_ids("redshift", cluster),
                internet_reachable=bool(cluster.get("PubliclyAccessible")),
                raw=cluster,
            )

    topology.classify_sensitive()
    return topology


def _glob(base, *parts):
    pattern = os.path.join(base, *parts)
    import glob

    return glob.glob(pattern, recursive=True)


def _tag_name(tags):
    for tag in tags or []:
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            return tag.get("Value")
    return None


def load_model(source, name=None, sensitive_ids=None):
    """Dispatch a file path / dict / topology to a ReachabilityModel."""
    if isinstance(source, ReachabilityModel):
        return source
    if isinstance(source, Topology):
        return model_from_topology(source)
    if isinstance(source, str) and os.path.isdir(source):
        topology = topology_from_account_data(source, name=name)
        return model_from_topology(topology)

    elements = load_graph_data(source)
    # A normalized topology spec is a dict with resources/security_groups.
    if isinstance(elements, dict) and (
        "resources" in elements or "security_groups" in elements
    ):
        return model_from_topology(topology_from_spec(elements))
    return model_from_cytoscape(elements, name=name, sensitive_ids=sensitive_ids)


# ---------------------------------------------------------------------------
# Path enumeration
# ---------------------------------------------------------------------------

def _opening_matches(opening, protocol, port):
    if protocol is not None:
        wanted = normalize_protocol(protocol)
        if opening.get("protocol") != "all" and wanted != opening.get("protocol"):
            return False
    return port_allowed(port, opening.get("from_port"), opening.get("to_port"))


def enumerate_paths(
    model,
    target_ids=None,
    port=None,
    protocol=None,
    max_hops=6,
    max_paths=1000,
    require_verified=False,
    flow_wide_port=False,
):
    """Enumerate simple internet -> target paths in the model."""
    internet_sources = sorted(model.internet_sources) or [INTERNET_CIDR]
    if target_ids is None:
        target_ids = {
            node_id
            for node_id, node in model.nodes.items()
            if node.get("sensitive")
        }
    target_ids = set(target_ids)

    results = []

    def dfs(current, node_path, hop_openings, visited):
        if len(results) >= max_paths:
            return
        if current in target_ids and len(node_path) >= 2:
            final_openings = hop_openings[-1] if hop_openings else []
            matching_final = [
                opening
                for opening in final_openings
                if _opening_matches(opening, protocol, port)
                and (not require_verified or opening.get("verified"))
            ]
            if port is not None or protocol is not None:
                if not matching_final:
                    return
            if require_verified and not all(
                opening.get("verified")
                for openings in hop_openings
                for opening in openings
            ):
                return
            results.append((list(node_path), list(hop_openings)))
            # Sensitive targets generally do not originate further paths, but
            # keep walking if they also have outgoing edges.

        if len(node_path) - 1 >= max_hops:
            return

        for nxt in sorted(model.adjacency.get(current, {}).keys()):
            if nxt in visited:
                continue
            openings = model.adjacency[current][nxt]
            usable = [
                opening
                for opening in openings
                if not require_verified or opening.get("verified")
            ]
            if flow_wide_port and (port is not None or protocol is not None):
                usable = [
                    opening
                    for opening in usable
                    if _opening_matches(opening, protocol, port)
                ]
            if not usable:
                continue
            visited.add(nxt)
            node_path.append(nxt)
            hop_openings.append(usable)
            dfs(nxt, node_path, hop_openings, visited)
            hop_openings.pop()
            node_path.pop()
            visited.discard(nxt)

    for source in internet_sources:
        dfs(source, [source], [], {source})

    # De-duplicate by node sequence (DFS already yields unique sequences) and
    # sort deterministically.
    results.sort(key=lambda item: tuple(item[0]))
    return results


def _risk_for_hops(hop_count, verified):
    if not verified:
        return "review"
    if hop_count <= 1:
        return "critical"
    if hop_count == 2:
        return "high"
    if hop_count == 3:
        return "medium"
    return "low"


def build_path_dicts(model, enumerated):
    paths = []
    for index, (node_path, hop_openings) in enumerate(enumerated, start=1):
        hops = []
        all_verified = True
        for hop_number, (source_id, target_id, openings) in enumerate(
            zip(node_path[:-1], node_path[1:], hop_openings), start=1
        ):
            serialized_openings = []
            for opening in sorted(
                openings,
                key=lambda item: (
                    str(item.get("protocol")),
                    item.get("from_port") or -1,
                    item.get("to_port") or -1,
                    str(item.get("sg_id")),
                ),
            ):
                opening_dict = dict(opening)
                serialized_openings.append(opening_dict)
                if not opening_dict.get("verified", True):
                    all_verified = False
            first = serialized_openings[0] if serialized_openings else {}
            hops.append(
                AttrDict(
                    hop=hop_number,
                    source=source_id,
                    target=target_id,
                    openings=serialized_openings,
                    # Convenience summary fields (first/most permissive opening)
                    protocol=first.get("protocol"),
                    from_port=first.get("from_port"),
                    to_port=first.get("to_port"),
                    port=first.get("port"),
                    security_group=first.get("sg_id"),
                    security_group_name=first.get("sg_name"),
                    source_kind=first.get("source_kind"),
                    source_value=first.get("source_value"),
                    verified=all(o.get("verified", True) for o in serialized_openings),
                )
            )
        target_id = node_path[-1]
        target_node = model.nodes.get(target_id, {})
        path = AttrDict(
            id="path-{:03d}".format(index),
            account=model.name,
            source=node_path[0],
            target=target_id,
            target_name=target_node.get("name", target_id),
            target_type=target_node.get("type"),
            sensitive=bool(target_node.get("sensitive")),
            nodes=node_path,
            path=list(node_path),
            node_count=len(node_path),
            hop_count=len(hops),
            hops=hops,
            ports=sorted(
                {
                    opening.get("port")
                    for openings in hop_openings
                    for opening in openings
                    if opening.get("port")
                }
            ),
            rule_verified=all_verified,
            confidence="verified" if all_verified else "inferred",
            risk=_risk_for_hops(len(hops), all_verified),
        )
        paths.append(path)
    return paths


# ---------------------------------------------------------------------------
# Analyzer / report
# ---------------------------------------------------------------------------

class ReachabilityAnalyzer(object):
    """High level facade.

    Parameters mirror :meth:`analyze` and may be set on the instance.
    """

    def __init__(
        self,
        port=None,
        protocol=None,
        sensitive_only=True,
        sensitive_ids=None,
        sensitive_resources=None,
        max_hops=6,
        max_paths=1000,
        require_verified=False,
        flow_wide_port=False,
    ):
        self.port = port
        self.protocol = protocol
        self.sensitive_only = sensitive_only
        self.sensitive_ids = set(sensitive_ids or sensitive_resources or [])
        self.max_hops = max_hops
        self.max_paths = max_paths
        self.require_verified = require_verified
        self.flow_wide_port = flow_wide_port

    def analyze(self, source, name=None, **overrides):
        options = AttrDict(
            port=self.port,
            protocol=self.protocol,
            sensitive_only=self.sensitive_only,
            sensitive_ids=set(self.sensitive_ids),
            max_hops=self.max_hops,
            max_paths=self.max_paths,
            require_verified=self.require_verified,
            flow_wide_port=self.flow_wide_port,
        )
        options.update(overrides)
        sensitive_ids = options.sensitive_ids or None
        model = load_model(source, name=name, sensitive_ids=sensitive_ids)

        if options.sensitive_only:
            target_ids = {
                node_id
                for node_id, node in model.nodes.items()
                if node.get("sensitive") or node_id in (sensitive_ids or set())
            }
            target_ids.update(sensitive_ids or set())
        else:
            target_ids = {
                node_id
                for node_id in model.targets()
                if not model.nodes.get(node_id, {}).get("is_internet")
                and not model.nodes.get(node_id, {}).get("is_cidr")
            }

        enumerated = enumerate_paths(
            model,
            target_ids=target_ids,
            port=options.port,
            protocol=options.protocol,
            max_hops=options.max_hops,
            max_paths=options.max_paths,
            require_verified=options.require_verified,
            flow_wide_port=options.flow_wide_port,
        )
        paths = build_path_dicts(model, enumerated)

        sensitive_resources = [
            _resource_summary(node_id, model.nodes[node_id])
            for node_id in sorted(model.nodes)
            if model.nodes[node_id].get("sensitive")
        ]
        reachable_targets = sorted({path.target for path in paths})
        report = AttrDict(
            schema=SCHEMA_VERSION,
            account=model.name,
            source=INTERNET_CIDR,
            options={
                "port": options.port,
                "protocol": normalize_protocol(options.protocol),
                "sensitive_only": options.sensitive_only,
                "max_hops": options.max_hops,
            },
            summary={
                "nodes": len(model.nodes),
                "edges": sum(len(v) for v in model.adjacency.values()),
                "security_groups": len(model.security_groups),
                "sensitive_resources": len(sensitive_resources),
                "reachable_sensitive_resources": len(reachable_targets),
                "paths": len(paths),
                "verified_paths": sum(1 for path in paths if path.rule_verified),
            },
            sensitive_resources=sensitive_resources,
            reachable_resources=reachable_targets,
            paths=paths,
            findings=paths,
            reachable_paths=paths,
        )
        report["path_keys"] = [tuple(path.nodes) for path in paths]
        return report


def _resource_summary(node_id, node):
    return AttrDict(
        id=node_id,
        name=node.get("name", node_id),
        type=node.get("type"),
        sensitive=bool(node.get("sensitive")),
        internet_reachable=bool(node.get("internet_reachable") or node.get("is_internet")),
    )


def analyze_reachability(source, name=None, **options):
    """Functional shorthand for :class:`ReachabilityAnalyzer`."""
    return ReachabilityAnalyzer(**{k: v for k, v in options.items() if k in _ANALYZER_FIELDS}).analyze(
        source, name=name
    )


_ANALYZER_FIELDS = {
    "port",
    "protocol",
    "sensitive_only",
    "sensitive_ids",
    "sensitive_resources",
    "max_hops",
    "max_paths",
    "require_verified",
    "flow_wide_port",
}


def get_reachable_paths(source, **options):
    """Return just the list of reachable path dictionaries."""
    return analyze_reachability(source, **options)["paths"]


def find_paths(source, target=None, port=None, protocol=None, **options):
    """Convenience helper targeting one resource id/arn."""
    sensitive_ids = set(options.pop("sensitive_ids", None) or [])
    if target is not None:
        sensitive_ids.add(target)
    return analyze_reachability(
        source,
        port=port,
        protocol=protocol,
        sensitive_ids=sensitive_ids or None,
        **options
    )["paths"]


# Common alternative names callers/tests may look for.
ReachabilityEngine = ReachabilityAnalyzer
ReachabilityAnalysis = ReachabilityAnalyzer
ReachabilityGraph = ReachabilityModel
calculate_reachability = analyze_reachability
analyse_reachability = analyze_reachability
find_reachable_paths = analyze_reachability
build_reachability_report = analyze_reachability
compute_reachable_paths = get_reachable_paths


# Defined after the incremental store class (see below); alias attached there.


# ---------------------------------------------------------------------------
# Incremental store
# ---------------------------------------------------------------------------

class IncrementalReachability(object):
    """Cache analysis per account and emit diffs when SG rules change.

    The store can be persisted as JSON so an external process / CI job can
    update rules incrementally across runs.
    """

    def __init__(self, state_path=None, **analyzer_options):
        self.state_path = state_path
        self.analyzer_options = analyzer_options
        self.accounts = {}
        # Runtime-only Topology cache; never serialized into the state file.
        self._topologies = {}
        if state_path and os.path.isfile(state_path):
            self.load(state_path)

    # -- account management -------------------------------------------------

    def add_account(self, name, source=None, topology=None):
        if topology is None:
            topology = source if isinstance(source, Topology) else topology_from_spec(source)
        topology.name = name
        self.accounts[name] = {
            "spec": topology.to_spec(),
            "sg_hashes": {
                sg_id: sg_fingerprint(sg)
                for sg_id, sg in topology.security_groups.items()
            },
            "version": 1,
            "report": None,
        }
        self._topologies[name] = topology
        return self.analyze(name)

    def _topology_for(self, name):
        topology = self._topologies.get(name)
        if topology is None:
            topology = topology_from_spec(self.accounts[name]["spec"])
            topology.name = name
            self._topologies[name] = topology
        return topology

    def add_account_from_directory(self, name, directory):
        if os.path.isfile(os.path.join(directory, "topology.json")):
            topology = topology_from_spec(_load_json_file(os.path.join(directory, "topology.json")))
        else:
            topology = topology_from_account_data(directory, name=name)
        topology.name = name
        return self.add_account(name, topology=topology)

    def account_names(self):
        return sorted(self.accounts)

    # -- analysis -----------------------------------------------------------

    def analyze(self, name=None, force=False):
        if name is not None:
            return self._analyze_account(name, force=force)
        return {name: self._analyze_account(name, force=force) for name in sorted(self.accounts)}

    def _analyze_account(self, name, force=False):
        record = self.accounts[name]
        if record["report"] is not None and not force:
            return AttrDict(copy.deepcopy(record["report"]), cached=True)
        topology = topology_from_spec(record["spec"])
        report = ReachabilityAnalyzer(**self.analyzer_options).analyze(
            topology, name=name
        )
        report["version"] = record["version"]
        serialized = copy.deepcopy(report)
        serialized["path_keys"] = [list(key) for key in report.path_keys]
        record["report"] = serialized
        result = AttrDict(copy.deepcopy(serialized))
        result["cached"] = False
        return result

    def cached_report(self, name):
        return copy.deepcopy(self.accounts[name]["report"])

    # -- incremental rule updates -------------------------------------------

    def update_security_group(self, name, security_group):
        record = self.accounts[name]
        topology = self._topology_for(name)
        sg_id = security_group.get("GroupId") or security_group.get("id")

        old_report = record.get("report")
        old_keys = {tuple(key) for key in (old_report or {}).get("path_keys", [])}
        old_adjacency = model_from_topology(topology).adjacency
        old_edge_keys = {
            (source, target)
            for source, targets in old_adjacency.items()
            for target in targets
        }

        change = topology.apply_security_group_change(security_group)
        if not change.changed:
            report = self._analyze_account(name)
            return AttrDict(
                account=name,
                changed=False,
                incremental=True,
                changed_security_groups=[],
                paths_added=[],
                paths_removed=[],
                paths_unchanged=len(old_keys),
                report=report,
            )

        # Persist the mutated spec + refreshed hashes.
        record["spec"] = topology.to_spec()
        record["sg_hashes"][sg_id] = change.new_hash
        record["version"] += 1

        new_model = model_from_topology(topology)
        new_edge_keys = {
            (source, target)
            for source, targets in new_model.adjacency.items()
            for target in targets
        }
        report = ReachabilityAnalyzer(**self.analyzer_options).analyze(
            topology, name=name
        )
        new_keys = {tuple(key) for key in report.path_keys}

        added_keys = sorted(new_keys - old_keys)
        removed_keys = sorted(old_keys - new_keys)
        unchanged_keys = old_keys & new_keys

        # Paths whose evidence or endpoints involve the changed SG.  These are
        # the paths a fine grained incremental engine would have to re-check.
        affected_old_keys = set()
        attached_resources = set(topology.resources_by_sg.get(sg_id, set()))
        for key in old_keys:
            if any(node in attached_resources for node in key):
                affected_old_keys.add(tuple(key))
                continue
            old_path = _find_path_by_nodes(old_report, key)
            if old_path and any(
                hop.get("security_group") == sg_id for hop in old_path.get("hops", [])
            ):
                affected_old_keys.add(tuple(key))

        report["version"] = record["version"]
        serialized = copy.deepcopy(report)
        serialized["path_keys"] = [list(key) for key in report.path_keys]
        record["report"] = serialized

        return AttrDict(
            account=name,
            changed=True,
            incremental=True,
            version=record["version"],
            changed_security_groups=[sg_id],
            added_security_groups=[sg_id] if change.added else [],
            edges_added=sorted(["{} -> {}".format(s, t) for s, t in new_edge_keys - old_edge_keys]),
            edges_removed=sorted(["{} -> {}".format(s, t) for s, t in old_edge_keys - new_edge_keys]),
            affected_path_keys=[list(key) for key in sorted(affected_old_keys)],
            paths_added=[_path_summary(report, key) for key in added_keys],
            paths_removed=[_removed_path_summary(old_report, key) for key in removed_keys],
            added_path_keys=[list(key) for key in added_keys],
            removed_path_keys=[list(key) for key in removed_keys],
            paths_unchanged=len(unchanged_keys),
            paths_added_count=len(added_keys),
            paths_removed_count=len(removed_keys),
            report=AttrDict(copy.deepcopy(serialized)),
        )

    def update_security_groups(self, name, security_groups):
        """Apply several SG updates, returning the aggregate diff."""
        aggregate = None
        for sg in security_groups:
            diff = self.update_security_group(name, sg)
            if aggregate is None:
                aggregate = diff
            else:
                aggregate.changed_security_groups.extend(diff.changed_security_groups)
                aggregate.paths_added.extend(diff.paths_added)
                aggregate.paths_removed.extend(diff.paths_removed)
                aggregate.added_path_keys.extend(diff.added_path_keys)
                aggregate.removed_path_keys.extend(diff.removed_path_keys)
                aggregate.paths_added_count += diff.paths_added_count
                aggregate.paths_removed_count += diff.paths_removed_count
                aggregate.report = diff.report
        return aggregate

    def refresh_from_directory(self, name, directory):
        """Diff the SG rules currently on disk against cached state."""
        if os.path.isfile(os.path.join(directory, "topology.json")):
            latest = topology_from_spec(
                _load_json_file(os.path.join(directory, "topology.json"))
            )
        else:
            latest = topology_from_account_data(directory, name=name)
        current_hashes = {
            sg_id: sg_fingerprint(sg) for sg_id, sg in latest.security_groups.items()
        }
        cached_hashes = self.accounts[name]["sg_hashes"]
        changed_ids = [
            sg_id
            for sg_id, digest in current_hashes.items()
            if cached_hashes.get(sg_id) != digest
        ]
        removed_ids = sorted(set(cached_hashes) - set(current_hashes))
        diffs = []
        for sg_id in changed_ids:
            diffs.append(self.update_security_group(name, latest.security_groups[sg_id]))
        for sg_id in removed_ids:
            # Replace with an empty SG so all its rules disappear.
            diffs.append(
                self.update_security_group(
                    name, {"GroupId": sg_id, "IpPermissions": []}
                )
            )
        return AttrDict(
            account=name,
            changed_security_groups=changed_ids,
            removed_security_groups=removed_ids,
            updates=diffs,
        )

    # -- persistence --------------------------------------------------------

    def save(self, state_path=None):
        state_path = state_path or self.state_path
        if not state_path:
            raise ValueError("No state_path configured for IncrementalReachability")
        payload = {
            "schema": SCHEMA_VERSION + "+state",
            "analyzer_options": self.analyzer_options,
            "accounts": self.accounts,
        }
        directory = os.path.dirname(os.path.abspath(state_path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(state_path, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, default=list)
        return state_path

    def load(self, state_path=None):
        state_path = state_path or self.state_path
        with open(state_path) as handle:
            payload = json.load(handle)
        self.accounts = payload.get("accounts", {})
        self._topologies = {}
        options = payload.get("analyzer_options")
        if options and not self.analyzer_options:
            self.analyzer_options = options
        return self


ReachabilityStore = IncrementalReachability


def _find_path_by_nodes(report, node_key):
    if not report:
        return None
    for path in report.get("paths", []):
        if tuple(path.get("nodes", [])) == tuple(node_key):
            return path
    return None


def _path_summary(report, node_key):
    path = _find_path_by_nodes(report, node_key)
    if path is not None:
        return {
            "path": list(node_key),
            "target": path.get("target"),
            "target_name": path.get("target_name"),
            "risk": path.get("risk"),
        }
    return {"path": list(node_key)}


def _removed_path_summary(old_report, node_key):
    return _path_summary(old_report, node_key)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def render_text(report):
    lines = []
    reports = report.get("accounts") if isinstance(report, dict) else None
    if reports:
        for account_report in reports:
            lines.extend(_render_account_text(account_report))
            lines.append("")
    else:
        lines.extend(_render_account_text(report))
    return "\n".join(lines).rstrip() + "\n"


def _render_account_text(report):
    lines = []
    title = "Account: {}".format(report.get("account") or "(graph)")
    lines.append(title)
    lines.append("=" * len(title))
    summary = report.get("summary", {})
    lines.append(
        "Sensitive resources: {sensitive} | reachable from {source}: {reachable} | paths: {paths} (verified {verified})".format(
            sensitive=summary.get("sensitive_resources", 0),
            source=report.get("source", INTERNET_CIDR),
            reachable=summary.get("reachable_sensitive_resources", 0),
            paths=summary.get("paths", 0),
            verified=summary.get("verified_paths", 0),
        )
    )
    for path in report.get("paths", []):
        chain = " -> ".join(_short(node) for node in path.nodes)
        lines.append(
            "[{id}] ({risk}/{confidence}) {chain}".format(
                id=path.id,
                risk=path.risk,
                confidence=path.confidence,
                chain=chain,
            )
        )
        for hop in path.hops:
            lines.append(
                "      hop {n}: {src} -> {dst} {port} via {kind}:{value} ({sg})".format(
                    n=hop.hop,
                    src=_short(hop.source),
                    dst=_short(hop.target),
                    port=hop.port or "all",
                    kind=hop.source_kind or "rule",
                    value=hop.get("source_value") or "-",
                    sg=hop.security_group or hop.security_group_name or "edge",
                )
            )
    if not report.get("paths"):
        lines.append("No internet reachable paths to sensitive resources found.")
    return lines


def _short(node_id):
    node_id = str(node_id)
    if _looks_like_cidr(node_id):
        return node_id
    if ":instance/" in node_id:
        remainder = node_id.split(":instance/", 1)[1]
        return remainder.split("/", 1)[0]
    if "/" in node_id:
        node_id = node_id.rsplit("/", 1)[-1]
    elif ":" in node_id:
        node_id = node_id.rsplit(":", 1)[-1]
    # CloudMapper duplicates ELB/RDS nodes per subnet and appends the subnet id.
    node_id = re.sub(r"\.?subnet-[0-9a-f]+$", "", node_id)
    return node_id or str(node_id)


def render_markdown(report):
    lines = ["# Reachability report", ""]
    reports = report.get("accounts") if isinstance(report, dict) and report.get("accounts") else [report]
    for account_report in reports:
        lines.append("## Account `{}`".format(account_report.get("account") or "(graph)"))
        summary = account_report.get("summary", {})
        lines.append(
            "- Sensitive resources: **{}**".format(summary.get("sensitive_resources", 0))
        )
        lines.append(
            "- Reachable sensitive resources: **{}**".format(
                summary.get("reachable_sensitive_resources", 0)
            )
        )
        lines.append("- Paths: **{}**".format(summary.get("paths", 0)))
        lines.append("")
        if account_report.get("paths"):
            lines.append("| Path | Risk | Confidence | Hops/ports |")
            lines.append("| --- | --- | --- | --- |")
            for path in account_report.paths:
                chain = " -> ".join(_short(node) for node in path.nodes)
                ports = ", ".join(path.ports)
                lines.append(
                    "| `{}` | {} | {} | {} |".format(
                        chain, path.risk, path.confidence, ports or "-"
                    )
                )
        else:
            lines.append("_No internet -> sensitive paths._")
        lines.append("")
    return "\n".join(lines)


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=True, default=list)
