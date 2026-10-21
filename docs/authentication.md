# Sign-in: local, LDAP / Active Directory, TACACS+ (ISE)

Adding a provider is configuration, not code (`infra/.env`, a secret file, a CA file). RBAC is
always enforced by the server; only *who you are* and, optionally, *which roles you hold* come
from the directory.

## How sign-in decides

| Situation | Result |
|---|---|
| A **local** account exists | local password (Argon2id). A local account never consults a directory — keep at least one local admin as the break-glass account |
| A **directory** account exists (`ldap` / `tacacs`) | the password is checked by that provider; if it is not enabled in `DF_AUTH_PROVIDERS`, sign-in fails |
| Unknown username | the external providers are tried in `DF_AUTH_PROVIDERS` order. If the directory grants roles, the account is created on the spot (no local password); otherwise an administrator must create it first |
| The directory manages roles (LDAP group mapping / TACACS+ role attribute) | the account's roles are **replaced** at every sign-in; no mapped role = no access |
| The directory does not manage roles | the roles an administrator assigned locally (Administration → Users) apply |

Every outcome is audited (`auth.login` with the provider and, on failure, the reason:
`invalid_credentials`, `no_role`, `not_provisioned`, `provider_disabled`, `inactive`,
`provider_unavailable: ...`). The browser always sees the same `invalid_credentials`. The login
throttle applies to every provider. Directory accounts have no local password (no change /
reset in the UI).

## LDAP / Active Directory

```
DF_AUTH_PROVIDERS=local,ldap
DF_LDAP_URL=ldaps://dc1.corp.local            # or ldap://... with DF_LDAP_START_TLS=true
DF_LDAP_BIND_DN=CN=svc-doctor-firewall,OU=Service,DC=corp,DC=local
DF_LDAP_USER_BASE=OU=People,DC=corp,DC=local
DF_LDAP_GROUP_ROLES=viewer=CN=DF-Viewers,OU=Groups,DC=corp,DC=local;optimizer=CN=DF-Optimizers,OU=Groups,DC=corp,DC=local;approver=CN=DF-Approvers,OU=Groups,DC=corp,DC=local;admin=CN=DF-Admins,OU=Groups,DC=corp,DC=local
```

* `infra/secrets/ldap_bind_password` — the service account's password (read-only search).
* `infra/trust/ldap-ca.pem` — the CA that signs the domain controllers' certificates. The
  certificate and host name are always verified; plain LDAP is refused.
* Flow: service bind → search `DF_LDAP_USER_FILTER` (default
  `(&(objectClass=user)(sAMAccountName={username}))`, the value escaped) — exactly one entry,
  else refused → bind as the user → roles from `memberOf` (direct membership; nest the DF
  groups directly). Empty passwords are refused before any bind (an empty LDAP password is an
  unauthenticated bind that would "succeed").

## TACACS+ (Cisco ISE)

```
DF_AUTH_PROVIDERS=local,tacacs
DF_TACACS_HOST=ise1.corp.local
DF_TACACS_PORT=49
DF_TACACS_SERVICE=shell
DF_TACACS_ROLE_ATTRIBUTE=df-role
```

* `infra/secrets/tacacs_secret` — the shared secret of the network device entry.
* ISE: add Doctor Firewall as a network device (TACACS+ enabled, the shared secret above).
  Device Admin policy set → authentication against AD / internal users; authorization result =
  a *TACACS profile* (task attribute view, "Shell") with the custom attribute
  `df-role` = `viewer` | `optimizer` | `approver` | `admin` (several separated by commas).
* Flow: authentication `START` (PAP) → `PASS` → authorization `REQUEST` with
  `service=shell` → roles from `df-role`. With `DF_TACACS_ROLE_ATTRIBUTE=` (empty) no
  authorization is requested and roles stay local.
* RFC 8907 obfuscates the body with the shared secret (MD5 pad) — this is not encryption:
  keep TACACS+ on the management network. Replies without obfuscation are rejected.

## Where the configuration lives

`infra/.env` (see `infra/.env.example`), secrets in `infra/secrets/` (created empty by
`init-secrets`; fill them in), CA in `infra/trust/`. Restart the stack after changes
(`docker compose ... up -d api`). A wrong configuration stops the API at start-up with the
reason (fail closed).
