# Inspection by destination tier (phase 6)

Access and inspection are two layers (doctrine): the access rule decides *whether* a flow is
allowed, the inspection profile *what is done* to an allowed flow. They are crossed by the tier
of the **destination** — east-west included (a SILVER application calling a GOLD database gets
GOLD inspection). The system proposes **where** inspection belongs; turning a profile on is an
approved, deployed change like any other.

| Destination tier | Decryption | IPS | File / malware |
|---|---|---|---|
| CORE | never (do-not-decrypt, at the top of the SSL policy) | light / none | no |
| GOLD | inbound known-key | full, aggressive (*Maximum Detection*) | yes |
| SILVER | selective | full or balanced (at least *Balanced*) | yes |
| BRONZE | by exposure | balanced (at least *Balanced*) | optional |

Code: `backend/app/analysis/inspection.py`; executor operation `set_inspection` in
`backend/app/enforce/`.

## Inspection profiles

*Policies → Inspection profiles* maps each tier to the FMC intrusion and file policy that
implement it (names as they appear in the FMC; the lists come from the latest snapshot).
Defaults, until configured: GOLD *Maximum Detection*, SILVER *Security Over Connectivity*,
BRONZE *Balanced Security and Connectivity*; no file policy (there is no built-in one).
Changes apply at the next analysis. Editing needs `conventions:manage` (admin).

Intrusion policy strength is judged against Cisco's built-in policies — *Connectivity Over
Security* (1) < *Balanced* (2) < *Security Over Connectivity* (3) < *Maximum Detection* (4) — by
name, else by the custom policy's base policy. A custom policy that matches none of them is not
judged (no proposal to replace it).

## Recommendation kinds

| Kind | When | Executable |
|---|---|---|
| `add_inspection` | an enabled permit access rule (not shadowed, not dead) whose destination is GOLD / SILVER / BRONZE has no intrusion policy, a weaker one than the tier's profile, or (GOLD / SILVER) no file policy. A **Trust** rule becomes **Allow** — trusted traffic skips Snort | yes: one rule update (`set_inspection`) |
| `ssl_exempt_core` | in a decryption policy, a decrypt rule (resign or known-key) catches traffic to CORE systems not exempted by an earlier do-not-decrypt rule. AD / Kerberos, LDAPS and pinned updates break under decryption | no — proposal: a do-not-decrypt rule for those systems at the top |
| `ssl_decrypt_inbound` | GOLD / SILVER systems reached over TLS (TCP 443, 8443, 9443, 636, 993, 995, 465, TLS applications, or any service) by permit rules, but no known-key rule in the decryption policy covers them (or there is no decryption policy) — the IPS is blind to the payload | no — proposal: a known-key rule for those systems |

Decryption rules stay manual on purpose: known-key needs each server's certificate and private
key in the FMC, and its renewal is an operational dependency the system cannot own.

## Writing (`set_inspection`)

The operation carries the rule's action and intrusion / file policy ids from the snapshot; the
executor stops on any difference (drift). It sets `ipsPolicy` / `filePolicy` (and `action`
ALLOW for a Trust rule) and, when the rule has no variable set, the FMC's built-in
`Default-Set` (read from `/object/variablesets`). Verification reads the rule back; rollback
restores the original rule. Order inside a changeset: after tightening, before removals.
