# Backlog (agreed, not yet scheduled)

Items the product owner asked to handle later. Each entry: what, why, and what is known.

## B-001 — Collect the device routing table (runtime, incl. BGP-learned routes)
*Requested 2026-10-20. **Done 2026-10-26** — see [architecture.md](architecture.md#collection-phase-1) ("Runtime routing table").*

**Why:** automatic rule opening derives zone and network from source/destination IPs. Today only
connected networks (from interfaces) and static routes are known; routes learned via BGP/OSPF are
missing, so lookups for networks reached through dynamic routing are incomplete.

**Known:** the FMC configuration API exposes interfaces, static routes and BGP neighbour settings,
not the live routing table. Candidate sources to evaluate (none assumed yet): an FMC operational /
device-query endpoint for routes if available in 10.1, or a read-only "show route" equivalent
through the FMC. Must stay read-only and respect the FMC API limits.

**Done when:** each snapshot stores per-cluster effective routes (connected, static, dynamic with
source protocol), and IP -> zone/interface resolution uses them.
