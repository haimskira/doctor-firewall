# Controlled enforcement (phase 5)

The only path by which Doctor Firewall changes the FMC. Read-only stays the default: nothing
is written without an accepted recommendation, a changeset with a ticket id, a batch approved by
someone other than the author, and an explicit *run*.

```
recommendation --accept (optimizer)--> changeset (ticket id) --> batches <= deploy limit
   --approve (approver != author)--> run --> drift check, write, verify, deploy, poll
                                        \--> on any failure: undo in reverse, redeploy, report
```

## 1. Executable plans

Every recommendation carries a plan — operations from a closed set, each with the FMC ids and
the **expected current state** (`expect`):

| Operation | FMC call | Expect checked before writing |
|---|---|---|
| `create_object` | `POST /object/{hosts,networks,ranges,protocolportobjects,networkgroups}` | — |
| `update_group` | `GET` + `PUT /object/networkgroups/{id}` | name, member identities |
| `rename_object` | `GET` + `PUT /object/{type}/{id}` | name |
| `delete_object` | `GET` + `DELETE` | name (the FMC also refuses objects still in use) |
| `update_rule` | `GET` + `PUT …/accessrules/{id}` (or prefilterrules) | name, identities of the fields changed |
| `create_rule` | `GET` source + `POST …/accessrules?insertAfter=<index>&section=…&category=…` | source name and fields |
| `delete_rule` | `GET` + `DELETE` | name |

References created earlier in the same plan (`temp`) are resolved at execution. A `PUT`
replaces the whole object: the writer copies the current object and changes only the planned
fields. Anything the writer cannot do safely makes the plan **not executable** with a reason
(`route_reference` — an object used by a static route, `unsupported_rule_kind:nat` …); such
recommendations cannot enter a changeset.

## 2. Changesets and batches

* Built by an optimizer from **accepted** recommendations of the **latest** snapshot of a
  connection; requires a title and a ticket id (`[A-Za-z0-9._/-]`, stored in the audit trail
  of every step).
* **Conflicts are refused, never merged:** two recommendations touching the same rule or object,
  or one deleting what another uses (`409 conflicting_recommendations` with the pairs).
* A recommendation already in an open changeset cannot be staged twice.
* **Batches:** every recommendation stays whole inside one batch (a split is never half
  deployed). Safe order: object creations and reference rewrites, rule changes, renames, then
  deletions. Each batch's operation count is at most the smallest **deploy change limit** of the
  clusters it affects (rule changes affect the clusters governed by the policy; shared objects
  affect all). The limit is re-checked when the batch runs. A recommendation larger than the
  limit is refused (`item_exceeds_limit`).
* The changeset keeps its own copy of every plan: retention deleting the snapshot does not
  change what was approved.

## 3. Approval

* `deploy:approve` (role *approver*) — and **never the changeset's author** (four eyes; a user
  holding both roles still cannot approve their own changeset).
* Strictly in order: batch *n* only after batch *n-1* is deployed.
* Cancel (author side) stops everything not yet run.

## 4. Running a batch

`POST /api/changesets/{id}/batches/{seq}/run` (approver, not the author) queues the job on the
`enforce` queue. The executor:

1. re-validates: batch approved, changeset open, operation count within the current limit;
2. takes the **write lock** of that FMC (`df:fmc-write:<host>:<port>` in Redis, owner token,
   TTL) — one writer per FMC across all workers; if busy, the batch stays *approved*;
3. for each operation: `GET` the object, compare with `expect` (**drift** stops the batch before
   that write), write (one at a time; 429 is retried with back-off), record the undo step;
4. **verifies** every touched object by reading it back;
5. **deploys** the affected HA pairs / devices (`deployabledevices` → `deploymentrequests`) and
   polls `job/taskstatuses/{id}` until *Deployed* (timeout `DF_DEPLOY_TIMEOUT_SECONDS`);
6. on any failure in 3–5: **undo** in reverse order (re-created objects get new ids, which are
   mapped into later undo steps), redeploy the restored configuration, and end `rolled_back` —
   or `failed` with the steps that could not be undone, so an operator can finish by hand.

Every step is audited (`changeset.create`, `batch_approve`, `batch_run`,
`batch_deployed` / `batch_rolled_back` / `batch_failed` with ticket id, approver and task id).

## Not done automatically (by design)

* Static routes, NAT, decryption and identity rules are never rewritten (plans are blocked).
* FMC change-management tickets are not created; the ticket id is carried in Doctor
  Firewall's audit trail. *To verify* with the FMC team whether FMC change management is enabled
  — then the writer must open / approve a ticket around each batch.
* The deploy change limit's unit (operations vs deploy items) is *to verify* on the real FMC
  (D-015).
