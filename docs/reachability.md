# Reachability analysis (internet → sensitive resources)

The `reachability` command answers the question the topology map cannot:
**which ordered paths can an attacker take from the public internet, through
security-group-allowed lateral movement, to a sensitive data store?**

It re-derives connectivity from EC2 security-group rules (CIDR rules and
source-security-group rules), records the exact protocol/port and rule
evidence for every hop, and can consume the existing Cytoscape graph produced
by `cloudmapper prepare` (`web/data.json`) without changing its format.

## Quick start

```bash
# One-command acceptance: 3 accounts vs hand-derived paths + incremental updates
bash acceptance.sh

# Analyze the three bundled acceptance accounts
python cloudmapper.py reachability --accounts shop,analytics,partner

# Analyze an existing prepare graph and write the web overlay
python cloudmapper.py reachability \
  --graph web/data.json --accounts demo \
  --web-overlay web/reachability.json

# Open the highlighted view
python cloudmapper.py webserver
# then browse to http://127.0.0.1:8000/reachability.html
```

`commands/reachability.py` can also be executed directly
(`python commands/reachability.py ...`) in environments where the full
CloudMapper dependency set (notably `pyjq`) is unavailable; the reachability
engine itself (`shared/reachability.py`) is standard-library only.

## How paths are reasoned

1. **Parse rules.** Every security group `IpPermissions` entry is normalized
   to protocol + port interval + sources (`IpRanges`, `Ipv6Ranges`,
   `UserIdGroupPairs`). Simplified documents (`cidr`, `source_sg`, `port`,
   `ingress_rules`) are accepted as well.
2. **Build adjacency.**
   - `0.0.0.0/0` / `::/0` rules create an internet edge only when the target
     is actually internet reachable (public IP, `internet-facing` ELB,
     `PubliclyAccessible` RDS/Redshift). A private-only host with an open
     `0.0.0.0/0` SG rule is therefore **not** reported as an entry point.
   - CIDR rules connect resources whose IP falls inside the range.
   - Source-SG rules connect every resource carrying the source group to
     every resource carrying the target group.
3. **Classify sensitive targets.** `rds`, `rds_rr`, `redshift`,
   `elasticsearch`/`opensearch`, `elasticache`, `docdb`, `neptune`,
   `memorydb`, name patterns (`db`, `mysql`, `postgres`, `redshift`, ...),
   `Sensitive=true` tags, and explicit id/ARN lists.
4. **Enumerate simple paths** from the internet to sensitive targets. Each
   path carries per-hop openings, the responsible security group, risk and
   whether every hop was directly verified from a rule.

By default `--port P` tests reachability of the **final** service port
(intermediate management ports such as SSH remain stepping stones). Use
`flow_wide_port=True` in the API to constrain every hop.

## Compatibility with existing graph data

`ReachabilityAnalyzer().analyze("web/data.json")` reads the established
`[{"data": {"id"|"source"/"target", "type", "node_data", ...}}]` Cytoscape
document. Edge `node_data` written by `prepare` is the list of security
groups that justified the edge; the adapter re-matches the exact permission
(CIDR membership or source SG) to recover ports. When an edge has no
re-matchable rule detail it is retained and marked `confidence: inferred`
instead of being silently dropped.

Raw `account-data/<account>/<region>/ec2-describe-security-groups.json` plus
EC2/ELB/ELBv2/RDS/Redshift inventories can also be loaded directly via
`topology_from_account_data()`, and a normalized
[`topology.json`](../tests/fixtures/reachability/accounts/shop/topology.json)
format is supported for compact fixtures.

## Three-account acceptance oracle

The fixtures under
[`tests/fixtures/reachability/accounts/`](../tests/fixtures/reachability/accounts/)
are three independent accounts whose expected paths were derived by hand and
documented in each `manual_reasoning.md`:

| Account | Scenario | Expected internet → sensitive paths |
| --- | --- | --- |
| `shop` (111111111111) | bastion/web → app → DB | `internet → bastion → app → db-orders`; `internet → web → app → db-orders` |
| `analytics` (222222222222) | SG pairs + broad `10.10/16` rule | `internet → jump → rs-bi`; `internet → jump → worker → rs-bi` (locked RDS unreachable) |
| `partner` (333333333333) | ELB chain + exposed RDS + private false positive | `internet → elb-partner → api → es-partner`; `internet → rds-leak` |

`tests/unit/test_reachability_acceptance.py` asserts these exact node
sequences and per-hop ports against **all three inputs**: normalized
`topology.json`, `prepare`-compatible `graph.json`, and raw account snapshots.

## Incremental rule updates

`IncrementalReachability` fingerprints each security group. When a rule
changes it rebuilds only the openings provenanced to that security group,
bumps an account `version`, and diffs the new path set against the cached
one (`paths_added`, `paths_removed`, unchanged count, edge diffs, affected
paths). State persists to JSON so separate CI runs can update incrementally:

```python
from shared.reachability import IncrementalReachability

store = IncrementalReachability(state_path="artifacts/reachability-state.json")
store.add_account_from_directory("shop", "tests/fixtures/reachability/accounts/shop")

diff = store.update_security_group("shop", changed_sg_document)
print(diff.added_path_keys, diff.removed_path_keys)
store.save()
```

CLI form:

```bash
python cloudmapper.py reachability --accounts shop,analytics,partner \
  --state artifacts/reachability-state.json

python cloudmapper.py reachability --accounts shop,analytics,partner \
  --state artifacts/reachability-state.json \
  --update-sg shop=/path/to/new-sg-shop-web.json
```

`refresh_from_directory(account, path)` compares on-disk SG fingerprints and
applies only the changed groups. Rule changes in one account never invalidate
cached results for other accounts.

## Web visualization

`web/reachability.html` highlights every internet-to-sensitive path on top of
the graph data, lists paths by risk, and shows per-hop security-group evidence
when a path or edge is selected. It loads `web/reachability-demo.json` (the
three acceptance accounts) by default and falls back to `web/data.json` +
`web/reachability.json`; graph/report files can also be opened from the
picker without a server.

## API reference (short)

```python
from shared.reachability import (
    ReachabilityAnalyzer,          # aka ReachabilityEngine / ReachabilityAnalysis
    analyze_reachability,          # aka calculate_reachability / find_reachable_paths
    get_reachable_paths,
    IncrementalReachability,       # aka ReachabilityStore
    model_from_cytoscape,
    topology_from_account_data,
)

report = analyze_reachability("web/data.json", port=5432)
for path in report["paths"]:
    print(path["nodes"], [hop["port"] for hop in path["hops"]])
```
