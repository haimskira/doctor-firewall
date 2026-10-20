# Rule score and phase-2 analysis

## Rule score (0–100)

Computed for every **enabled permit rule** (ALLOW / TRUST) of an access policy; deny, monitor
and disabled rules are not scored. The score starts at 100; each deduction is stored with its
code and shown to the operator — no black box. Source: `backend/app/analysis/score.py`.

| Code | Points | Doctrine principle |
|---|---|---|
| `any_destination` | 25 | The rule is anchored on its destination |
| `broad_destination` | 10 | Destination > 256 addresses: stingy with the destination |
| `any_source` | 15 | Least privilege |
| `broad_source` | 10 | Source > 65,536 addresses |
| `any_service` | 15 | Any port and any application |
| `wide_ports` | 5 | More than 100 destination ports |
| `multi_tier_destination` | 20 | One destination tier per rule |
| `gold_many_sources` | 15 | GOLD = few, precise sources (> 1,024 addresses or any) |
| `gold_without_ips` | 10 | GOLD gets full inspection |
| `gold_without_file_policy` | 5 | GOLD gets file / malware inspection |
| `silver_without_ips` | 5 | SILVER gets inspection |
| `tier_skip` | 30 | East-west only least → most sensitive, never skipping (bronze → gold) |
| `shadowed` | 20 | The rule can never match |
| `dead` | 10 | No hits (zero, or none within `DF_DEAD_RULE_DAYS`, default 90) |
| `inline_literals` | 5 | Rules never contain raw IPs |
| `ace_heavy` | 5 | Expands to more than 1,000 ACEs |
| `no_logging` | 5 | A permit rule without logging |
| `unclassified_destination` | 0 | Information: part of the destination is not in the asset table |

Tiers come from the **confirmed** asset table only (bootstrap suggestions do not count until an
operator confirms them). CORE is outside the tiers; USERS is the user space (with `user_type`).

## Shadowing and overlaps

Each first-match list (access, prefilter, decryption) is evaluated in order on exact match
spaces (addresses as merged intervals, ports per protocol, zones / applications / SGTs / URLs /
users / VLANs as sets):

* **shadowed_rule** — an earlier enabled, terminating rule covers every dimension of a later rule.
  Same verdict → medium (redundant); opposite verdict → high (conflict).
* **overlap_conflict** — an earlier rule with the opposite verdict matches part of a later rule
  (up to 3 reported per rule).
* MONITOR rules never shadow (they log and continue).
* Conservative by design: FQDNs and objects without a resolvable value are opaque — a rule
  containing one is never reported as shadowed unless the earlier rule contains the same object.

## ACE expansion

Per rule: the product of the leaf counts of source zones, destination zones, source networks,
destination networks, source ports and destination ports ("any" counts as 1) — the way the FMC
flattens object groups into Lina ACEs. Per cluster: the sum over the enabled rules of the access
and prefilter policies that govern it, compared with the cluster's ACE limit
(**ace_cluster_limit** at 80 % / 100 %). Limits are per cluster (`/api/clusters/{id}/limits`);
until an operator sets and verifies them, the default (`DF_DEFAULT_ACE_LIMIT`, 1,000,000) is
reported as an *unverified default*. With Object Group Search enabled on a device the real ACE
count is lower; the estimate is then an upper bound.

## Performance

Shadowing / overlap detection indexes earlier rules by the smallest CIDR block enclosing their
IPv4 destination (blocks are nested or disjoint), with an integer pre-filter on the source block;
the naive O(n²) algorithm is kept as the test oracle (randomised equivalence tests). Measured per
policy on one core: 10,000 rules with distinct destinations ≈ 0.2 s; a deliberately hostile
10,000-rule policy where every destination nests under a few broad blocks ≈ 13 s (was 55 s).
