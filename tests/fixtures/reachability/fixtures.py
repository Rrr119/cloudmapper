"""Three hand-reasoned acceptance accounts.

Every account describes a small AWS environment plus the paths a human
analyst derived from the security group rules.  ``MANUAL_EXPECTATIONS`` is the
oracle used by the acceptance tests; it is written independently from the
analysis engine.
"""
from __future__ import absolute_import

INTERNET = "0.0.0.0/0"


def sg(group_id, name, *permissions):
    return {"GroupId": group_id, "GroupName": name, "IpPermissions": list(permissions)}


def allow_cidr(protocol, from_port, to_port, cidr=INTERNET):
    return {
        "IpProtocol": protocol,
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": cidr}],
    }


def allow_sg(protocol, from_port, to_port, source_sg):
    return {
        "IpProtocol": protocol,
        "FromPort": from_port,
        "ToPort": to_port,
        "UserIdGroupPairs": [{"GroupId": source_sg}],
    }


ACCOUNTS = [
    # ------------------------------------------------------------------
    # Account 1: classic web + bastion -> app -> database chain
    # ------------------------------------------------------------------
    {
        "name": "shop",
        "account_id": "111111111111",
        "title": "Shop production (bastion and web tiers)",
        "narrative": [
            "The bastion and the web server each have a public IP and a "
            "0.0.0.0/0 ingress rule (SSH/22 and HTTPS/443).",
            "The app security group accepts 22 from the bastion group and "
            "8080 from the web group.",
            "The orders database only accepts PostgreSQL/5432 from the app "
            "group, so it is reachable only through one of the two chains.",
        ],
        "security_groups": [
            sg("sg-shop-web", "shop-web", allow_cidr("tcp", 443, 443)),
            sg("sg-shop-bastion", "shop-bastion", allow_cidr("tcp", 22, 22)),
            sg(
                "sg-shop-app",
                "shop-app",
                allow_sg("tcp", 8080, 8080, "sg-shop-web"),
                allow_sg("tcp", 22, 22, "sg-shop-bastion"),
            ),
            sg("sg-shop-db", "shop-db", allow_sg("tcp", 5432, 5432, "sg-shop-app")),
        ],
        "resources": [
            {
                "id": "bastion",
                "name": "shop-bastion",
                "type": "ec2",
                "sg_ids": ["sg-shop-bastion"],
                "private_ips": ["10.1.1.10"],
                "public_ips": ["54.1.1.1"],
            },
            {
                "id": "web",
                "name": "shop-web",
                "type": "ec2",
                "sg_ids": ["sg-shop-web"],
                "private_ips": ["10.1.2.20"],
                "public_ips": ["54.1.1.2"],
            },
            {
                "id": "app",
                "name": "shop-app",
                "type": "ec2",
                "sg_ids": ["sg-shop-app"],
                "private_ips": ["10.1.3.30"],
            },
            {
                "id": "db-orders",
                "name": "shop-db-orders",
                "type": "rds",
                "sg_ids": ["sg-shop-db"],
                "private_ips": ["10.1.4.40"],
            },
        ],
    },
    # ------------------------------------------------------------------
    # Account 2: SG-pair and broad-CIDR lateral movement
    # ------------------------------------------------------------------
    {
        "name": "analytics",
        "account_id": "222222222222",
        "title": "Analytics VPC (SG pairs plus a broad private CIDR rule)",
        "narrative": [
            "Only the jump host has a public IP; SSH/22 is open to 0.0.0.0/0.",
            "The worker accepts SSH from the jump security group.",
            "Redshift accepts 5439 from the jump group AND from the broad "
            "10.10.0.0/16 CIDR, which the worker (10.10.2.20) belongs to.",
            "The locked RDS only trusts an unused security group, so no "
            "path reaches it initially.",
            "Subtle transit: every 10.10.0.0/16 host (including the locked "
            "RDS at 10.10.4.40) is accepted by Redshift, so once the jump "
            "can reach the locked RDS it can also pivot onward to Redshift.",
        ],
        "security_groups": [
            sg("sg-an-jump", "analytics-jump", allow_cidr("tcp", 22, 22)),
            sg("sg-an-worker", "analytics-worker", allow_sg("tcp", 22, 22, "sg-an-jump")),
            sg(
                "sg-an-rs",
                "analytics-redshift",
                allow_sg("tcp", 5439, 5439, "sg-an-jump"),
                allow_cidr("tcp", 5439, 5439, "10.10.0.0/16"),
            ),
            sg("sg-an-locked", "analytics-locked-db", allow_sg("tcp", 5432, 5432, "sg-an-ghost")),
        ],
        "resources": [
            {
                "id": "jump",
                "name": "analytics-jump",
                "type": "ec2",
                "sg_ids": ["sg-an-jump"],
                "private_ips": ["10.10.1.10"],
                "public_ips": ["54.2.2.2"],
            },
            {
                "id": "worker",
                "name": "analytics-worker",
                "type": "ec2",
                "sg_ids": ["sg-an-worker"],
                "private_ips": ["10.10.2.20"],
            },
            {
                "id": "rs-bi",
                "name": "analytics-bi-redshift",
                "type": "redshift",
                "sg_ids": ["sg-an-rs"],
                "private_ips": ["10.10.3.30"],
            },
            {
                "id": "db-locked",
                "name": "analytics-locked-rds",
                "type": "rds",
                "sg_ids": ["sg-an-locked"],
                "private_ips": ["10.10.4.40"],
            },
        ],
    },
    # ------------------------------------------------------------------
    # Account 3: ELB chain, directly exposed RDS, private-only false positive
    # ------------------------------------------------------------------
    {
        "name": "partner",
        "account_id": "333333333333",
        "title": "Partner DMZ (internet-facing ELB and a leaked database)",
        "narrative": [
            "The internet-facing partner ELB accepts 443 from 0.0.0.0/0.",
            "The API instances accept 443 from the ELB group and can reach "
            "the Elasticsearch domain on 443.",
            "A publicly accessible RDS has 3306 open to 0.0.0.0/0: direct "
            "internet path.",
            "A private-only EC2 has 80 open to 0.0.0.0/0 at the SG layer but "
            "no public IP, so AWS routing makes it unreachable from the "
            "internet; it must not be reported as an entry point.",
        ],
        "security_groups": [
            sg("sg-p-ELB", "partner-elb", allow_cidr("tcp", 443, 443)),
            sg("sg-p-api", "partner-api", allow_sg("tcp", 443, 443, "sg-p-ELB")),
            sg("sg-p-es", "partner-es", allow_sg("tcp", 443, 443, "sg-p-api")),
            sg("sg-p-rdsopen", "partner-rds-open", allow_cidr("tcp", 3306, 3306)),
            sg("sg-p-hiddenweb", "partner-hidden-web", allow_cidr("tcp", 80, 80)),
        ],
        "resources": [
            {
                "id": "elb-partner",
                "name": "partner-elb",
                "type": "elbv2",
                "sg_ids": ["sg-p-ELB"],
                "internet_reachable": True,
            },
            {
                "id": "api",
                "name": "partner-api",
                "type": "ec2",
                "sg_ids": ["sg-p-api"],
                "private_ips": ["10.3.0.10"],
            },
            {
                "id": "es-partner",
                "name": "partner-es",
                "type": "elasticsearch",
                "sg_ids": ["sg-p-es"],
                "private_ips": ["10.3.2.20"],
            },
            {
                "id": "rds-leak",
                "name": "partner-leaked-rds",
                "type": "rds",
                "sg_ids": ["sg-p-rdsopen"],
                "internet_reachable": True,
            },
            {
                "id": "hidden",
                "name": "partner-private-only-web",
                "type": "ec2",
                "sg_ids": ["sg-p-hiddenweb"],
                "private_ips": ["10.3.9.9"],
                "internet_reachable": False,
            },
        ],
    },
]


# Human derived oracle.  Hop ports are listed in path order.
MANUAL_EXPECTATIONS = {
    "shop": {
        "sensitive_resources": ["db-orders"],
        "reachable_sensitive_resources": ["db-orders"],
        "unreachable_sensitive_resources": [],
        "paths": [
            {
                "nodes": [INTERNET, "bastion", "app", "db-orders"],
                "hop_ports": ["22/tcp", "22/tcp", "5432/tcp"],
            },
            {
                "nodes": [INTERNET, "web", "app", "db-orders"],
                "hop_ports": ["443/tcp", "8080/tcp", "5432/tcp"],
            },
        ],
    },
    "analytics": {
        "sensitive_resources": ["db-locked", "rs-bi"],
        "reachable_sensitive_resources": ["rs-bi"],
        "unreachable_sensitive_resources": ["db-locked"],
        "paths": [
            {
                "nodes": [INTERNET, "jump", "rs-bi"],
                # Final hop has both the SG-pair and broad-CIDR realization.
                "hop_ports": ["22/tcp", "5439/tcp"],
            },
            {
                "nodes": [INTERNET, "jump", "worker", "rs-bi"],
                "hop_ports": ["22/tcp", "22/tcp", "5439/tcp"],
            },
        ],
    },
    "partner": {
        "sensitive_resources": ["es-partner", "rds-leak"],
        "reachable_sensitive_resources": ["es-partner", "rds-leak"],
        "unreachable_sensitive_resources": [],
        "paths": [
            {
                "nodes": [INTERNET, "elb-partner", "api", "es-partner"],
                "hop_ports": ["443/tcp", "443/tcp", "443/tcp"],
            },
            {
                "nodes": [INTERNET, "rds-leak"],
                "hop_ports": ["3306/tcp"],
            },
        ],
        "must_not_contain_nodes": [[INTERNET, "hidden"]],
    },
}


# Incremental rule-change scenarios (also manually reasoned).
INCREMENTAL_SCENARIOS = {
    "shop": {
        "description": "Delete the public HTTPS rule on the web SG; only the bastion chain survives.",
        "sg_change": sg("sg-shop-web", "shop-web"),
        "removed": [[INTERNET, "web", "app", "db-orders"]],
        "added": [],
        "remaining": [[INTERNET, "bastion", "app", "db-orders"]],
    },
    "analytics_add_trust": {
        "account": "analytics",
        "description": (
            "Let the jump host reach the locked RDS: a direct path appears, "
            "plus a pivot from that RDS through the broad-CIDR rule to Redshift."
        ),
        "sg_change": sg(
            "sg-an-locked",
            "analytics-locked-db",
            allow_sg("tcp", 5432, 5432, "sg-an-ghost"),
            allow_sg("tcp", 5432, 5432, "sg-an-jump"),
        ),
        "removed": [],
        "added": [
            [INTERNET, "jump", "db-locked"],
            [INTERNET, "jump", "db-locked", "rs-bi"],
        ],
        "remaining": [
            [INTERNET, "jump", "rs-bi"],
            [INTERNET, "jump", "worker", "rs-bi"],
            [INTERNET, "jump", "db-locked"],
            [INTERNET, "jump", "db-locked", "rs-bi"],
        ],
    },
    "analytics_lock_jump": {
        "account": "analytics",
        "description": "Restrict SSH on the jump host to an office CIDR: all paths disappear.",
        "sg_change": sg(
            "sg-an-jump",
            "analytics-jump",
            allow_cidr("tcp", 22, 22, "198.51.100.0/24"),
        ),
        "removed": [
            [INTERNET, "jump", "rs-bi"],
            [INTERNET, "jump", "worker", "rs-bi"],
            [INTERNET, "jump", "db-locked"],
            [INTERNET, "jump", "db-locked", "rs-bi"],
        ],
        "added": [],
        "remaining": [],
    },
}


def account_by_name(name):
    for account in ACCOUNTS:
        if account["name"] == name:
            return account
    raise KeyError(name)
