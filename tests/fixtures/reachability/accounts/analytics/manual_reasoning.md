# Manual reasoning - Analytics VPC (SG pairs plus a broad private CIDR rule) (`222222222222`)

- Only the jump host has a public IP; SSH/22 is open to 0.0.0.0/0.
- The worker accepts SSH from the jump security group.
- Redshift accepts 5439 from the jump group AND from the broad 10.10.0.0/16 CIDR, which the worker (10.10.2.20) belongs to.
- The locked RDS only trusts an unused security group, so no path reaches it initially.
- Subtle transit: every 10.10.0.0/16 host (including the locked RDS at 10.10.4.40) is accepted by Redshift, so once the jump can reach the locked RDS it can also pivot onward to Redshift.

## Expected internet -> sensitive paths

| # | Path | Hop ports |
| - | ---- | --------- |
| 1 | `0.0.0.0/0 -> jump -> rs-bi` | `22/tcp, 5439/tcp` |
| 2 | `0.0.0.0/0 -> jump -> worker -> rs-bi` | `22/tcp, 22/tcp, 5439/tcp` |

Reachable sensitive resources: `rs-bi`
Unreachable sensitive resources: `db-locked`

## Incremental rule changes

### `analytics_add_trust`

Let the jump host reach the locked RDS: a direct path appears, plus a pivot from that RDS through the broad-CIDR rule to Redshift.

- adds `0.0.0.0/0 -> jump -> db-locked`
- adds `0.0.0.0/0 -> jump -> db-locked -> rs-bi`
- keeps `0.0.0.0/0 -> jump -> rs-bi`
- keeps `0.0.0.0/0 -> jump -> worker -> rs-bi`
- keeps `0.0.0.0/0 -> jump -> db-locked`
- keeps `0.0.0.0/0 -> jump -> db-locked -> rs-bi`

### `analytics_lock_jump`

Restrict SSH on the jump host to an office CIDR: all paths disappear.

- removes `0.0.0.0/0 -> jump -> rs-bi`
- removes `0.0.0.0/0 -> jump -> worker -> rs-bi`
- removes `0.0.0.0/0 -> jump -> db-locked`
- removes `0.0.0.0/0 -> jump -> db-locked -> rs-bi`
