# System dossier

One asset-table system at the centre: **who reaches it** and **what it reaches**, with the
services on every arrow (`TCP-443`, `UDP-53`) and the rules that allow each flow. Monitor →
Insights → *System dossier* (`/dossier`). Read-only; derived from the analysed snapshot.

## What counts as a flow

The permit flows of the attack surface (`app.analysis.attack.load_hops`): enabled ALLOW / TRUST
access rules and prefilter FASTPATH rules that can match (shadowed rules never do), narrowed by
zones to the networks routed behind them, plus a permitting policy default action. Only policies
some device enforces count, or exactly one policy when the page is scoped to it (its world).

| Direction | Condition | Peers |
|---|---|---|
| inbound | the flow's destination overlaps the system | its sources |
| outbound | the flow's source overlaps the system | its destinations |
| internal | both sides inside the system's own addresses | counted, not drawn |

## Peers

A peer is what the **rule** names on the other side, so a computer outside the asset table still
appears under its FMC object name:

| Kind | When |
|---|---|
| `system` | another asset-table system the other side's addresses touch |
| `object` | an FMC object or literal on the other side that is not entirely inside asset systems |
| `network` | the rule says *any* there, narrowed by its zones to routed networks |
| `any` | any address |
| `default` | the policy's default action permits |

Per peer: addresses, services as protocol-port (from the rule's modelled destination ports) and
applications, the system's components it touches, identity conditions (SGT / dynamic object /
user: "only for"), hits, worst risk (the connectivity map colours), rule counts and a sample of
the rules with links to the policy editor.

A flow is **broad** when its side at the system is wider than the system (a rule written for
`10.0.0.0/8` or *any*): the system is reachable, but not through a rule made for it. The page can
hide peers reached only that way.

## Limits

300 peers per direction (the busiest first: kinds, then risk, then hits) and 25 rules listed per
peer; counts are always exact. The page draws 25 peers per side until "show all". On phone-width
screens it opens on the table view.

API: `GET /api/snapshots/{id}/dossier?system=TIER|name[&policy=][&cluster=]` (docs/api.md).
