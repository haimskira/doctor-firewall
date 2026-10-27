# Traffic proof

`app/enforce/proof.py` answers one question for a batch: does any flow get a different verdict?

## Model

For every access and prefilter policy: the ordered rules (enabled, action, intrusion policy,
file policy, and the objects / literals of every match field), the objects and the group
memberships. The *after* model applies the batch's operations: rules updated, created in place
(after their anchor), deleted, inspection set; groups' members replaced, objects created or
deleted. During execution the *after* model is instead built from what the FMC returns when the
touched rules and objects are read back.

A flow's verdict is the first enabled rule that matches it — MONITOR rules log and let the
evaluation continue — or the policy's default action: the action, plus the intrusion and file
policy for traffic that is let through (TRUST and FASTPATH skip inspection).

## Why the probe flows are enough

A rule is *touched* when it is created, deleted, or its verdict or match space changed — the
latter also when a group it uses changed, at any nesting depth. If a flow's verdict changes,
the rule that decided it before or after is touched (an untouched rule matches the same flows and
keeps its relative order). So only flows inside touched rules matter.

Inside that region every dimension — source and destination address, service (protocol and
port, or a token such as an ICMP type), source port, zones, applications, URLs, SGTs, dynamic
objects, users, VLANs — is cut where any overlapping rule starts or ends. Within one cell of that
grid every rule matches all of it or none of it, so one flow per cell decides the cell. The
probes are one flow per cell:

* **exhaustive** (≤ 20 000 cells per touched rule): a proof for the modelled dimensions;
* **sampled** above that: the grid is thinned evenly, and the report says so.

Not modelled: application detection inside allowed services, URL reputation, time ranges — rules
are compared on the values they list.

## Validation

On the lab rulebase (3 006 rules) all 245 preserving recommendations checked (nine kinds) showed
no difference with exhaustive proofs, 3–5 s each; every add_inspection plan showed its change.
Unit tests include a wrong merge across a block rule and a group change reaching every rule that
uses the group.
