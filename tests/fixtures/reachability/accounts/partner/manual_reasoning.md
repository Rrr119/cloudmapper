# Manual reasoning - Partner DMZ (internet-facing ELB and a leaked database) (`333333333333`)

- The internet-facing partner ELB accepts 443 from 0.0.0.0/0.
- The API instances accept 443 from the ELB group and can reach the Elasticsearch domain on 443.
- A publicly accessible RDS has 3306 open to 0.0.0.0/0: direct internet path.
- A private-only EC2 has 80 open to 0.0.0.0/0 at the SG layer but no public IP, so AWS routing makes it unreachable from the internet; it must not be reported as an entry point.

## Expected internet -> sensitive paths

| # | Path | Hop ports |
| - | ---- | --------- |
| 1 | `0.0.0.0/0 -> elb-partner -> api -> es-partner` | `443/tcp, 443/tcp, 443/tcp` |
| 2 | `0.0.0.0/0 -> rds-leak` | `3306/tcp` |

Reachable sensitive resources: `es-partner, rds-leak`
Unreachable sensitive resources: `(none)`

## Incremental rule changes
