# Inspection: one IPS, one file policy, one decryption policy (phase 6)

Access and inspection are two layers (doctrine): the access rule decides *whether* a flow is
allowed, the inspection *what is done* to an allowed flow. The organisation has **one**
intrusion policy, **one** file policy and **one** decryption policy: no per-tier profiles. The
tier of the **destination** (east-west included) only decides *whether* a rule needs more
inspection and how urgent it is. The system proposes **where** inspection belongs; attaching a
policy is an approved, deployed change like any other.

| Destination tier | IPS (the organisation's policy) | File / malware | Decryption |
|---|---|---|---|
| CORE: identity (AD / DC, PKI) | yes | no | never (do-not-decrypt, at the top of the SSL policy) |
| CORE: DNS, patching | yes | no | never |
| CORE: NTP | none: proposed for fastpath | no | never |
| GOLD | yes | yes | Decrypt-Resign, HTTPS only |
| SILVER | yes | yes | Decrypt-Resign, HTTPS only |
| BRONZE | yes | no | no |

**IPS wherever it can run (maximum protection).** Every server tier gets the intrusion policy,
CORE included. The only exemption is traffic Snort would break or drown in **and** that stays
between known systems (see *Never IPS* below); traffic from the WAN, from users or from *any*
is never exempt. NTP to CORE is proposed for fastpath. A rule whose destination is not
classified in the asset table gets no proposal.

Code: `backend/app/analysis/inspection.py`; executor operation `set_inspection` in
`backend/app/enforce/`.

## The organisation profile

*Policies -> IPS and file policy* holds the one intrusion policy and the one file policy (names
as they appear in the FMC; the lists come from the latest snapshot). API:
`GET / PUT / DELETE /api/inspection-profile`; stored as one row (key `ALL`). A field left empty
is the policy most enabled ALLOW rules of the snapshot already carry (ties: by name), so a
network that already runs one policy needs no setup. When no such policy exists, or the chosen
one is not in the snapshot, the recommendation is **blocked** (`ips_profile_not_configured`,
`ips_profile_missing`, `file_profile_not_configured`, `file_profile_missing`). Changes apply at
the next analysis. Editing needs `conventions:manage` (admin).

There is no judgement of policy strength: a rule is fine when it carries the organisation's
intrusion policy; a rule carrying another one is proposed to **switch** (the title says which one
it has now).

## Recommendation kinds

IPS and file policy are **separate** recommendations. They write different fields and each
expects only its own, so both on one rule can be staged in one changeset and run one after the
other without a false drift. (Two IPS proposals, or two file proposals, on one rule still clash;
the second waits for the next changeset. Any other change to the rule clashes with both.)

| Kind | When | Executable |
|---|---|---|
| `add_inspection` | an enabled permit access rule (not shadowed, not dead, not a fastpath candidate) with a classified destination that does not carry the organisation's intrusion policy: none, another one (switch), or a **Trust** rule (becomes **Allow**: trusted traffic skips Snort) | yes: one rule update (`set_inspection`, expects action and intrusion policy) |
| `add_file_policy` | the same kind of rule whose destination is GOLD or SILVER and that has no file policy. A Trust rule waits: it becomes Allow first | yes: one rule update (`set_inspection`, expects the file policy only) |
| `fastpath_candidate` | an enabled permit access rule (not Trust, not shadowed / dead) whose **every** service is in `IPS_EXEMPT` and whose both ends are inside (table below) | no: proposal to move it to the prefilter (FASTPATH) or to Trust with logging; warning `fastpath_no_inspection`, blocked `fastpath_manual` |
| `ssl_exempt_core` | in a decryption policy, a decrypt rule (resign, or an existing known-key) catches traffic to CORE systems, or identity / management services by port (`NEVER_DECRYPT`: LDAPS 636, Global Catalog 3269, RADIUS over TLS 2083, sftunnel 8305, ISE pxGrid 8910), not exempted by an earlier do-not-decrypt rule (any port for systems, any address for services) | no: proposal `DND_CORE_SERVICES` / `DND_IDENTITY_MGMT_SERVICES` at the top |
| `ssl_decrypt_inbound` | **Decrypt-Resign for HTTPS**: GOLD / SILVER systems that permit rules allow HTTPS to (TCP/443, or an HTTPS / SSL application, or any service) and that the decryption policy linked to the access policy does not settle on 443. A decrypt rule (any action) reaching the system on 443 counts as decrypted; a do-not-decrypt rule covering it is a deliberate exclusion. Other TLS (8443, mail, LDAPS) is not HTTPS and never proposed; never CORE | no: proposal of **one** `DECRYPT_RESIGN` rule (destination: those systems, port TCP/443); warnings `resign_ca_trust`, `resign_pinning_mtls`, `resign_invalid_cert`; blocked `decryption_rule_manual` |

Known-key decryption is not proposed (it needs each server's certificate and private key in the
FMC and every renewal mirrored there). A known-key rule already in the FMC is still understood as
"decrypted".

## Never IPS

One of: the volume would overload Snort; the latency Snort adds would break the protocol; the
traffic runs between infrastructure devices and never comes from outside. A rule is a
`fastpath_candidate` only when **all** its services are in one of these classes:

| Class | Services | Both ends must be |
|---|---|---|
| storage | iSCSI TCP 3260, NFS TCP/UDP 2049 | DC systems of the asset table (CORE..BRONZE; no users, nothing unclassified) |
| replication | vMotion TCP 8000, VMware NFC TCP 902, SnapMirror TCP 11104-11105, SQL AlwaysOn TCP 5022 | DC systems |
| routing | BGP TCP 179, OSPF, EIGRP | explicit, at most 256 addresses (devices are often not in the asset table) |
| bfd | UDP 3784-3785, 4784 | at most 256 addresses |
| management | FMC-FTD sftunnel TCP 8305 | at most 256 addresses |
| ntp | NTP UDP 123 | destination CORE only; source explicit and in the asset table (users included), never any or outside |

Also never inspected, outside what the system proposes: Block rules (IPS runs on permit rules
only), the failover / state links (outside the ACP; check no broad rule catches them). SMB is
left out on purpose: it is a prime attack vector; only SMB to backup servers deserves an
exemption, a manual decision. No IPS is not "open": keep such rules narrow and logged.

## Never decrypt

Mutual TLS / client certificates (EAP-TLS, 802.1X over TLS); certificate pinning (mobile, cloud
clients, AV / EDR updates); identity (AD, LDAPS, Kerberos, RADIUS); ISE, FMC and device
management; unmanaged devices without the root CA (printers, IoT, OT, cameras, BYOD, guests);
encrypted backup / replication; VPN clients (IPsec / DTLS never reach the decryption policy).
Rule of thumb: critical infrastructure + managed, known devices + a decryption failure would
break more than it protects → do not decrypt. The system checks CORE systems and the
`NEVER_DECRYPT` ports; mTLS, pinning and unmanaged devices cannot be recognised by address and
port and stay a maintained manual list.

**Neither IPS nor decryption:** FMC-FTD management, and backup / replication / storage inside
the data centre.

Decryption rules stay manual on purpose: the internal CA used to re-sign is configured in the
FMC, and the system does not own it. The recommendation shows which rule to add and what it
should match. Under Decrypt-Resign: the internal CA must be trusted by every client; applications
with certificate pinning or mutual TLS break (exclude them with do-not-decrypt above the rule);
block invalid server certificates, since the client no longer sees the real one.

## Writing (`set_inspection`)

The operation carries only what it is about in `expect`: the action and intrusion policy id for
an IPS proposal, the file policy id for a file proposal (old plans carrying all three are still
read). The executor stops when what is expected differs in the FMC (drift) and verifies only
what it wrote. It sets `ipsPolicy` / `filePolicy` (and `action`
ALLOW for a Trust rule) and, when the rule has no variable set, the FMC's built-in
`Default-Set` (read from `/object/variablesets`). Verification reads the rule back; rollback
restores the original rule. Order inside a changeset: after tightening, before removals.
