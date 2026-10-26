# Lab: a real FMC, a messy rulebase, and the system cleaning it up

The end-to-end rehearsal of an operational deployment: build a large, messy, doctrine-shaped
rulebase in a LAB FMC, deploy it, give the system a clean slate, pull the mess and fix it with
the system's own approval / batch / deploy flow — exactly as it would run against a production
firewall in another network.

> Lab only. The tools below **write to the FMC and deploy**. They refuse to run without
> `--yes-write-to-lab`; passwords come from `DF_LAB_PASSWORD` (or stdin) and are never stored.

## 1. Reach the lab FMC (verified TLS)

A lab FMC usually presents a self-signed certificate issued to `firepower`:

```bash
# its certificate becomes a trust anchor (site-local, not in Git)
openssl s_client -connect <fmc-ip>:443 </dev/null 2>/dev/null | openssl x509 > infra/trust/extra-ca.pem
# its certificate name resolves inside the stack (site-local, not in Git)
cat > infra/docker-compose.local.yml <<EOF
services:
  api:    { extra_hosts: ["firepower:<fmc-ip>"] }
  worker: { extra_hosts: ["firepower:<fmc-ip>"] }
EOF
scripts/dev-up.sh            # builds certs/dev-trust.pem = dev CA + extra-ca.pem
```

Then add the FMC under *Integrations → FMC* with host `firepower`.

## 2. Build the mess (≈10 000 objects, 3 000 rules)

```bash
docker run --rm -e DF_LAB_PASSWORD --add-host firepower:<fmc-ip> \
  -v $PWD/infra/trust/extra-ca.pem:/ca.pem:ro -v $PWD/lab-work:/work doctor-firewall/api:dev \
  python -m app.tools.lab_scale --host firepower --user <api user> --ca /ca.pem \
  --policy <access policy> --deploy-limit 100 --yes-write-to-lab
```

* Address plan by the doctrine: CORE services, 20 GOLD systems, 40 SILVER and 40 BRONZE
  applications, 60 user segments, DMZ, partners — and the mess that accumulates: address-named
  duplicates, groups nested 8 deep with redundant members, groups mixing tiers, copies of groups,
  unused objects, ranges, FQDNs, duplicate port objects.
* 3 000 rules in 15 categories: sound rules, duplicates, broad rules shadowing narrow ones, runs
  of rules that differ only by source, rules spanning tiers, wide ports, inline values, BRONZE /
  users straight to GOLD, Trust to GOLD, GOLD without IPS, disabled leftovers, temporary any rules.
* Objects go in with the bulk API (1 000 per request); rules in chunks of `--deploy-limit`
  changes, **each chunk deployed and awaited** before the next — never more changes per
  deployment than the budget.
* `lab-work/manifest.json` records everything created (re-running resumes); `--cleanup` removes
  exactly that and deploys. `lab-work/assets.csv` is the scenario's asset table (doctrine tiers).
* `python -m app.tools.lab_seed` is the small version (≈60 objects, 16 rules).

## 3. Clean slate, pull, analyse

```bash
C="docker compose --project-directory infra -f infra/docker-compose.yml -f infra/docker-compose.dev.yml"
$C exec api python -m app.cli reset-data --yes    # snapshots, changesets, decisions, assets
```

Users, FMC connections, naming conventions, inspection profiles and the audit log stay. Import
`assets.csv` (Assets → Import CSV) — in production the organisation provides this table — then
pull the FMC and let the analysis run.

## 4. Fix it with the system

Recommendations → accept → stage a changeset (ticket id) → the system packs batches under each
cluster's deploy limit → a second user approves → run: drift-checked writes, verification,
deployment, automatic rollback on any failure. Pull again to confirm the result.

## Notes from the real FMC 10.1 lab

See [architecture.md](architecture.md#payload-validation-before-production). In particular: object
names are unique **ignoring case** (a built-in `TCP_high_ports` blocks `TCP_HIGH_PORTS`), and the
`section` and `category` query parameters may not be combined when inserting a rule.
