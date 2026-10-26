# Connectivity map (phase 4)

A dynamic map of who talks to whom, built from the local copy at analysis time (no live
traffic data). Source: `backend/app/analysis/connectivity.py` (edges, written by the analysis
job) and `backend/app/api/connectivity.py` (`GET /api/snapshots/{id}/map`).

## Nodes and edges

* **Nodes** are the assets of the confirmed asset table (`TIER|ASSET`; an asset's components
  share its node; stand-alone entries use their system name), grouped in columns by
  tier — users on the start side, then BRONZE → SILVER → GOLD → CORE (mirrored in Hebrew). Two
  special nodes: **Any** (a rule side without addresses) and **Not in the asset table**
  (addresses no asset covers, FQDNs, SGTs, dynamic objects, users).
* **Edges** come from every enabled *permit* access rule that can match (shadowed rules carry no
  traffic): one edge from each source node to each destination node. Edges are stored per policy
  so the cluster filter is exact, and aggregated per node pair in the API (rule count, hits,
  lowest score, up to 20 sample rules and services).

## Colours (doctrine)

| Colour | Meaning | Rule reasons |
|---|---|---|
| red — dangerous | a clear breach | `tier_skip` (bronze → gold), any → any, a dead rule that is still open |
| yellow — may be risky | works but deviates from the ideal | GOLD / SILVER without IPS or file policy, GOLD with many sources, any or wide service, any / broad source or destination, several destination tiers |
| green — compliant | — | none of the above |

An edge also records how many of its rules (and hits) carry each colour (`risk_rules`,
`risk_hits`). The **flow** view draws every connection split into its red / yellow / green
parts, so a connection with one dangerous rule among a hundred compliant ones is not painted
entirely red; the **graph** view keeps the worst colour per edge. The panel lists the reasons
("why this colour") and the rules, each linking to the policy editor.

## Views and filters

| View | Edges shown |
|---|---|
| Assets | all |
| System to system (east-west) | server tier → server tier |
| Users to systems (north-south) | USERS or Any → non-user nodes |

Filters: cluster; **from** / **to** an IP, subnet or range (a node matches when one of its
asset networks intersects the filter; *Any* always matches; *Not in the asset table* matches
when the filter is not fully covered by assets); **both directions** also keeps the reverse
pairs; risk (red / yellow / green). The API returns the riskiest 1,500 edges by default (5,000
max) and says when the list is truncated.

## Before / after of a recommendation

Rule recommendations (split, merge, tighten, remove dead rule) carry the node-level edges of the
involved rules before and after the change (`preview.map`). The recommendation panel draws both;
splits and merges keep the same node pairs (behaviour-preserving), tightening removes the *Any*
source, removing a dead rule removes its edges.

## Rendering

**Flows (default)** — a Sankey diagram drawn in SVG by our own code (no extra dependency): sources
on one side, destinations on the other (mirrored in Hebrew), nodes coloured by tier, band width
by rules or hits (toggle), bands split by risk colour; the 16 largest nodes per side are shown and
the rest folded into "+N more". Hover focuses a node or band, click opens the connection panel.
Next to it: riskiest connections, busiest destinations, top services. Colours come from the theme
tokens, so light and dark modes need no special handling.

**Graph** — Cytoscape.js 3.34.3 (MIT, no dependencies, bundled — no CDN) with a deterministic preset layout.
Cytoscape normally injects an inline `<style>`; the strict CSP (`style-src 'self'`) blocks it, so
the UI places a placeholder element that suppresses the injection and ships the rule in
`styles.css`. A table of the same edges is always shown under the graph (keyboard / screen
readers).
