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

## B-002 — Version 0.8: traffic logs and identity-aware recommendations
*Requested 2026-11-22, scheduled for 0.8 — after the FMC 10.1.1 collection failure is fixed.*

**Why:** today the system knows *whether* a rule matched (hit counts), not *what* went through it.
Recommendations for application control, SGT / dynamic objects and IPS tuning need real traffic.

**Scope, in order:**
1. **Connection events ingest** — a syslog receiver in the stack (FTD → syslog, end-of-connection
   events), aggregated to `source → destination → port → application → rule`, not raw events.
   Use: tighten *any* rules to the traffic actually seen (stronger than hit counts).
2. **Application control recommendation (the owner's design: an L7 canary)** —
   - *Step 1, preserving and executable:* insert a copy of the port rule **directly above it**
     with the proposed applications added (same sources, destinations, ports, action Allow,
     IPS / file policy, logging; name `<rule>_L7`). Anything the copy does not catch falls to
     the identical port rule below, so no flow changes (the traffic proof can show it).
   - *Watch:* the post-deploy hit-count watch follows the port rule below. Hits there = traffic
     the applications did not cover: the proposal needs fixing (connection events, item 1, say
     which application). Expect a small noise floor of sessions too short for identification
     (failed handshakes, scans): judge against a threshold, not zero.
   - *Step 2, behaviour-changing:* after a quiet window (hit counts reset on deploy / reboot, so
     the window starts at deploy), propose deleting the port rule; approval as for dead rules.
   - Applications: from connection events when available, else a port → application table
     (22 SSH, 3389 RDP, 1433 MSSQL, 443 HTTPS/SSL ...) marked "to verify". Never on Trust /
     fastpath rules (no Snort), never replacing ports with any. Warn when the copy doubles a
     heavy rule's ACEs during the watch.
3. **SGT / dynamic object recommendation** — propose replacing address lists with an SGT or a
   dynamic object where the sources form an identity group (today they are only read and shown).
4. **IPS events** — tuning: noisy / irrelevant signatures, profile too strong or too weak per tier.
5. **Network discovery** (optional) — fill the asset table (OS, services, applications per host)
   and compare ports in use to ports a rule opens.

**Known:** the FMC REST API does not return connection events; discovery data needs eStreamer
(to evaluate on 10.1.1). Must stay read-only toward the FMC and fully offline; volume handled by
aggregation and retention limits.
