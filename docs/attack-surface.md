# Attack surface and blast radius

*Monitor → Insights → Attack surface* (`/attack`). Pick a target — a system of the asset table,
or an IP address / network — and see every way the rulebase lets traffic reach it, hop by hop,
with the services, applications and rules of each hop. Switch the direction to see a **blast
radius**: everything a compromised source reaches, and everything those systems reach in turn.

Read-only: the analysis runs on a collected snapshot, never on the FMC.

## What counts as a hop

One permit rule that can match, as a flow from its sources to its destinations:

| Counted | Not counted |
|---|---|
| Enabled access rules with action ALLOW or TRUST | Disabled rules, BLOCK / MONITOR / … rules |
| Prefilter rules with action FASTPATH | Shadowed rules (an earlier rule takes all their traffic) |
| An access policy whose **default action** permits (an `any → any` hop, red) | Traffic inside one network (it never crosses the firewall) |

A hop whose rule is partly overridden by an earlier rule with the opposite verdict is marked
*partly decided by an earlier rule*: part of that traffic is blocked before it.

A hop whose rule also requires an identity — a **security group tag** (SGT), a **dynamic
object** or a **user** — lists it ("only for: source SGT: SGT_FIN_USERS"). The map is drawn
from addresses, so such a hop shows more reach than there is: only endpoints that carry that
tag / are mapped to that object get through.

Dynamic objects: the collector also reads each object's current mappings
(`GET object/dynamicobjects/{id}/mappings`) and the object page shows them. An orchestrator
changes them at runtime without a deploy, so the analysis (shadowing, the traffic proof, this
search) keeps the object as an opaque condition and never relies on those addresses.

## Pivots

`C → B → A` is a path only if the addresses of B that C may reach **overlap** the addresses of B
allowed to reach A. Example: if only `10.2.0.0/25` (half of system B) may reach A, and C may reach
only `10.2.0.128/25` (the other half), there is **no** path from C to A — even though "B" reaches
A and C reaches "B". The search runs on the rules' address sets; systems are only how the result
is drawn.

## The search

Layered, from the target (paths to it) or the source (blast radius):

1. hops whose destinations (sources) meet the current set → their sources (destinations) are one
   hop further;
2. repeat up to the chosen depth (1–4, default 3);
3. sources that are `any` are drawn as **Anywhere** (which includes the internet) and end a path;
4. in a blast radius, a hop whose destination is `any` (e.g. a forgotten `TEMP any-any` allow)
   reaches **every system** of the asset table plus *Anywhere* — the map shows them all on that
   ring, so one such rule is visible as what it is: everything exposed in one hop.

When the rings stop before the chosen depth, nothing new is reachable further out: every system
the next hop would reach is already on an inner ring (checked on the lab rulebase: servers rarely
start connections, so chains end after two hops once the any-any rule is removed).

Paths are listed most dangerous first. The score starts from where the path begins
(Anywhere 100, users 80, BRONZE 70, unclassified networks 60, SILVER 40, others 30), loses 10 per
extra hop, and adds for each of these, shown as reasons:

| Reason | Meaning |
|---|---|
| from / to anywhere | the path starts (ends) at `any` |
| direct / through another system | one hop, or a pivot |
| hop without IPS | some rule on the path has no intrusion policy |
| any service | some rule on the path allows any service |
| default action | the path relies on a permitting default action |
| skips a tier | the path jumps two or more tiers at once (e.g. BRONZE → GOLD) |
| partly blocked earlier | every hop is partly decided by earlier rules (score −5) |

## Limits

* Depth ≤ 4; at most 400 sets expanded per layer, 1 500 edges and 200 paths. When a cap is hit
  the page says so — narrow it with a cluster, a smaller depth or a smaller target.
* Rules are evaluated per policy, the prefilter first: a hop the first prefilter rule it meets
  blocks entirely is cut; one a prefilter BLOCK decides in part is marked *partly decided*.
* Zones narrow a rule's "any" (or wide) side to the networks routed behind them (interface
  subnets, static / connected / runtime routes); with a default route behind a zone nothing is
  narrowed.
* SGTs, dynamic objects, users and URLs cannot be placed on addresses: they never cut a path,
  the hop lists them ("only for ..."). The view stays an upper bound — what the rulebase *could*
  allow.

## API

```
GET /api/snapshots/{sid}/attack-surface/targets
GET /api/snapshots/{sid}/attack-surface?system=GOLD|SAP&mode=to&depth=3[&cluster=<id>]
GET /api/snapshots/{sid}/attack-surface?address=10.20.0.0/24&mode=from
GET /api/snapshots/{sid}/attack-surface?object=<object id>
```

Exactly one of `system`, `object` (an address object) or `address` (IP, CIDR or range; not
`0.0.0.0/0`). Permission `policy:read`. The permit hops of a snapshot are cached in the API
process until the snapshot is analysed again.
