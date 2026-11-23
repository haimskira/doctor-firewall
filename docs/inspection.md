# Inspection by destination tier (phase 6)

Access and inspection are two layers (doctrine): the access rule decides *whether* a flow is
allowed, the inspection profile *what is done* to an allowed flow. They are crossed by the tier
of the **destination** — east-west included (a SILVER application calling a GOLD database gets
GOLD inspection). The system proposes **where** inspection belongs; turning a profile on is an
approved, deployed change like any other.

| Destination tier | Decryption | IPS | File / malware |
|---|---|---|---|
| CORE: identity (AD / DC, PKI) | never (do-not-decrypt, at the top of the SSL policy) | the GOLD intrusion policy (*Maximum Detection*) | no |
| CORE: DNS, patching | never | at least *Balanced* (the CORE profile) | no |
| CORE: NTP | never | none: proposed for fastpath | no |
| GOLD | inbound known-key | full, aggressive (*Maximum Detection*) | yes |
| SILVER | selective | full or balanced (at least *Balanced*) | yes |
| BRONZE | by exposure | balanced (at least *Balanced*) | optional |

**IPS wherever it can run (maximum protection).** Every server tier gets IPS. CORE is a tier
for access, not for inspection: a rule to CORE whose every port is DNS (53) or WSUS (8530-8531)
gets the CORE profile; anything else (Kerberos, LDAP, Global Catalog, SMB, RPC, an unknown port,
any) counts as **identity** and gets the GOLD intrusion policy, without a file policy (AD is the
target of almost every advanced attack). NTP to CORE is proposed for fastpath. The only exemption is traffic
Snort would break or drown in **and** that stays between known systems (see *Never IPS* below);
traffic from the WAN, from users or from *any* is never exempt.

Code: `backend/app/analysis/inspection.py`; executor operation `set_inspection` in
`backend/app/enforce/`.

## Inspection profiles

*Policies → Inspection profiles* maps each tier to the FMC intrusion and file policy that
implement it (names as they appear in the FMC; the lists come from the latest snapshot).
Defaults, until configured: CORE *Balanced Security and Connectivity* (DNS / patching), GOLD *Maximum Detection*, SILVER *Security Over Connectivity*,
BRONZE *Balanced Security and Connectivity*; no file policy (there is no built-in one).
Changes apply at the next analysis. Editing needs `conventions:manage` (admin).

Intrusion policy strength is judged against Cisco's built-in policies — *Connectivity Over
Security* (1) < *Balanced* (2) < *Security Over Connectivity* (3) < *Maximum Detection* (4) — by
name, else by the custom policy's base policy. A custom policy that matches none of them is not
judged (no proposal to replace it).

## Recommendation kinds

| Kind | When | Executable |
|---|---|---|
| `add_inspection` | an enabled permit access rule (not shadowed, not dead, not a fastpath candidate) whose destination is GOLD / SILVER / CORE / BRONZE (most demanding first, in that order) has no intrusion policy, a weaker one than the tier's profile, or (GOLD / SILVER) no file policy. A **Trust** rule becomes **Allow** — trusted traffic skips Snort | yes: one rule update (`set_inspection`) |
| `fastpath_candidate` | an enabled permit access rule (not Trust, not shadowed / dead) whose **every** service is in `IPS_EXEMPT` and whose both ends are inside (table below) | no — proposal: move it to the prefilter (FASTPATH) or to Trust with logging; warning `fastpath_no_inspection`, blocked `fastpath_manual` |
| `ssl_exempt_core` | in a decryption policy, a decrypt rule (resign or known-key) catches traffic to CORE systems, or identity / management services by port (`NEVER_DECRYPT`: LDAPS 636, Global Catalog 3269, RADIUS over TLS 2083, sftunnel 8305, ISE pxGrid 8910), not exempted by an earlier do-not-decrypt rule (any port for systems, any address for services) | no — proposal: `DND_CORE_SERVICES` / `DND_IDENTITY_MGMT_SERVICES` at the top |
| `ssl_decrypt_inbound` | GOLD / SILVER systems reached over TLS (TCP 443, 8443, 9443, 993, 995, 465, TLS applications, or any service; not LDAPS, which is never decrypted) by permit rules, but no known-key rule in the decryption policy covers them (or there is no decryption policy) — the IPS is blind to the payload | no — proposal: a known-key rule for those systems |

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

Decryption rules stay manual on purpose: known-key needs each server's certificate and private
key in the FMC, and its renewal is an operational dependency the system cannot own.

## Writing (`set_inspection`)

The operation carries the rule's action and intrusion / file policy ids from the snapshot; the
executor stops on any difference (drift). It sets `ipsPolicy` / `filePolicy` (and `action`
ALLOW for a Trust rule) and, when the rule has no variable set, the FMC's built-in
`Default-Set` (read from `/object/variablesets`). Verification reads the rule back; rollback
restores the original rule. Order inside a changeset: after tightening, before removals.
