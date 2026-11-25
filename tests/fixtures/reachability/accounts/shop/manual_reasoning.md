# Manual reasoning - Shop production (bastion and web tiers) (`111111111111`)

- The bastion and the web server each have a public IP and a 0.0.0.0/0 ingress rule (SSH/22 and HTTPS/443).
- The app security group accepts 22 from the bastion group and 8080 from the web group.
- The orders database only accepts PostgreSQL/5432 from the app group, so it is reachable only through one of the two chains.

## Expected internet -> sensitive paths

| # | Path | Hop ports |
| - | ---- | --------- |
| 1 | `0.0.0.0/0 -> bastion -> app -> db-orders` | `22/tcp, 22/tcp, 5432/tcp` |
| 2 | `0.0.0.0/0 -> web -> app -> db-orders` | `443/tcp, 8080/tcp, 5432/tcp` |

Reachable sensitive resources: `db-orders`
Unreachable sensitive resources: `(none)`

## Incremental rule changes

### `shop`

Delete the public HTTPS rule on the web SG; only the bastion chain survives.

- removes `0.0.0.0/0 -> web -> app -> db-orders`
- keeps `0.0.0.0/0 -> bastion -> app -> db-orders`
