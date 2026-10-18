# fleetcore

fleetcore is an Apple MDM in one binary, built on NanoMDM and MongoDB: the MDM protocol, a SCEP certificate authority, enrollment profiles, TLS, Automated Device Enrollment, a JSON command API, blueprints (desired state with groups and staged rollouts), declarative device management, software update enforcement, and platform-aware profiles. It follows Apple's published definitions as they change. It stands alone: it needs a MongoDB replica set, an Apple push certificate and a public HTTPS name, and nothing else. Any product can manage it through its HTTP API.

Every endpoint is in [api-reference.md](api-reference.md). What is in the roadmap and what is not yet built is in [fleetcore-roadmap.md](fleetcore-roadmap.md).

## Run it

You need:

- MongoDB 6 or later as a replica set (a single node is a replica set of one; transactions need it).
- An Apple MDM push certificate (the topic looks like `com.apple.mgmt.External.<uuid>`).
- A public HTTPS name devices can reach, for example `https://mdm.example.com`.

```sh
docker run --rm fleetcore keygen            # a master key; keep it somewhere safe
FLEETCORE_URL=https://mdm.example.com \
FLEETCORE_API_KEY=$(openssl rand -hex 32) \
FLEETCORE_MASTER_KEY=<the key> \
docker compose -f deploy/fleetcore/compose.yaml up --build
```

Then upload the push certificate and key (`PUT /v1/pushcert`), and send a device to `https://mdm.example.com/enroll?code=<FLEETCORE_ENROLL_SECRET>`. **Enrollment is closed unless you open it:** set `FLEETCORE_ENROLL_SECRET` (a code people need), `FLEETCORE_ENROLL_AUTH_URL` (a forward-auth gate that decides), or `FLEETCORE_ENROLL_OPEN=1` (anyone who can reach the server gets a profile). ADE and account-driven enrollment authenticate the device or person themselves. Without Docker: `make fleetcore` builds the binary.

TLS can end at fleetcore (`-tls-cert`/`-tls-key`, or `-autocert host` for Let's Encrypt; devices then authenticate with the certificate they got from SCEP) or at a proxy in front (`-cert-source signature`: devices sign their requests, so the proxy needs nothing special).

## Configuration

Every option is a flag or an environment variable.

| Environment | Flag | |
| --- | --- | --- |
| `FLEETCORE_URL` | `-url` | public address devices use (required) |
| `FLEETCORE_MONGO_URI` | `-mongo` | MongoDB connection string |
| `FLEETCORE_DB` | `-db` | database name (default `fleetcore`) |
| `FLEETCORE_TENANT` | `-tenant` | tenant id, when tenants share a database; empty when the database belongs to one tenant |
| `FLEETCORE_TOPIC` | `-topic` | the push certificate's topic |
| `FLEETCORE_ORG` | `-org` | organization name on the CA and the profile |
| `FLEETCORE_CERT_SOURCE` | `-cert-source` | `tls`, `signature` or `header` |
| `FLEETCORE_TLS_CERT`, `FLEETCORE_TLS_KEY`, `FLEETCORE_AUTOCERT` | | TLS ends here |
| `FLEETCORE_API_KEY` | `-api-key` | management API key (basic auth; the password is the key, the user name is ignored) |
| `FLEETCORE_API_KEYS` | `-api-keys` | further keys as `name:key,name:key`; calls are logged and audited under the name |
| `FLEETCORE_ENROLL_SECRET`, `FLEETCORE_ENROLL_AUTH_URL`, `FLEETCORE_ENROLL_OPEN` | `-enroll-secret`, `-enroll-auth-url`, `-enroll-open` | who may download the enrollment profile; closed if none is set |
| `FLEETCORE_SEPARATE_CHECKIN`, `FLEETCORE_SCEP_VALIDITY_DAYS`, `FLEETCORE_CHALLENGE_TTL`, `FLEETCORE_ALLOW_RETROACTIVE` | `-separate-checkin`, `-scep-validity-days`, `-challenge-ttl`, `-allow-retroactive` | check-in at `/checkin`; identity certificate lifetime (365); SCEP challenge lifetime (24h); associate older enrollments with a certificate on their next check-in |
| `FLEETCORE_WEBHOOK_URL`, `FLEETCORE_WEBHOOK_HMAC_KEY` | `-webhook-url`, `-webhook-hmac-key` | MicroMDM-style event for every check-in and command report |
| `FLEETCORE_NO_METRICS`, `FLEETCORE_METRICS_TOKEN` | `-metrics`, `-metrics-token` | `/metrics` (on by default) and the bearer token a scraper uses |
| `FLEETCORE_RELAY_TYPES`, `FLEETCORE_EVENTS_ALLOW_PRIVATE` | `-relay-types`, `-events-allow-private` | event types the NATS and webhook sinks take; let subscriptions point at private addresses |
| `FLEETCORE_ADMIN_CA` | `-admin-ca` | management API requires a client certificate from this CA |
| `FLEETCORE_MONGO_CERT`, `FLEETCORE_MONGO_CA` | `-mongo-cert`, `-mongo-ca` | log in to MongoDB with a certificate |
| `FLEETCORE_TENANT_KEYS` | `-tenant-keys` | this tenant's encryption keys |
| `FLEETCORE_MASTER_KEY`, `FLEETCORE_MASTER_KEY_FILE` | `-master-key` | master keys (for a single-tenant server, or an operator) |
| `FLEETCORE_NO_FEEDS` | `-no-feeds` | do not contact Apple's schema, release and GDMF feeds |
| `FLEETCORE_UA_REALM`, `FLEETCORE_UA_USERS`, `FLEETCORE_UA_VERIFY_URL`, `FLEETCORE_UA_VERIFY_SECRET`, `FLEETCORE_UA_REQUIRE_TOKEN` | `-ua-realm`, `-ua-users`, `-ua-verify-url`, `-ua-verify-secret`, `-ua-require-token` | the UserAuthenticate handshake |
| `FLEETCORE_RELAY_NATS`, `FLEETCORE_RELAY_NATS_PREFIX`, `FLEETCORE_RELAY_JETSTREAM`, `FLEETCORE_RELAY_WEBHOOK`, `FLEETCORE_RELAY_WEBHOOK_SECRET` | `-relay-nats`, `-relay-nats-prefix`, `-relay-jetstream`, `-relay-webhook`, `-relay-webhook-secret` | the event relay |
| `FLEETCORE_MIGRATION`, `FLEETCORE_MIGRATE_CA` | `-migration`, `-migrate-ca` | accept enrollments from another NanoMDM-family server |

Subcommands for operators: `fleetcore keygen`, `fleetcore tenant-key`, `fleetcore mongo-user`, `fleetcore ua-hash`. `fleetcore -rekey` seals everything stored with the current key and exits.

## More of Apple's MDM

### Enrollment kinds

| Kind | Path | Notes |
| --- | --- | --- |
| Device enrollment (profile) | `/enroll` | SCEP identity (or ACME, below), one-use challenge |
| Automated Device Enrollment | `/enroll/ade` | the device's request is signed by Apple; the signature is checked to the Apple root, so a device DEP already knows needs no challenge; it can be held at Setup Assistant until blueprints finish (`await configuration`) |
| User Enrollment, account-driven (BYOD) | `/.well-known/com.apple.remotemanagement`, `/enroll/byod` | a Managed Apple Account signs in at your identity provider (`-byod-issuer`, `-byod-jwks`, `-byod-audience`, `-byod-claim`, `-byod-login-url`); the profile has no access rights; the schemas' `user_enrollment: forbidden` rules keep commands and payloads a User Enrollment cannot take from being sent |
| Managed Apple Account tokens | `GetToken` check-in | for ADE with a Managed Apple Account, signed by the DEP token key (`-maid-dep`) |

The enrollment type is recorded and blueprints can scope on it (a rule on `enrollment_type`), so a BYOD device gets only what its enrollment allows. `UserAuthenticate` (macOS network and mobile users, Shared iPad) is covered in its own section below.

### ADE follow-ups

Define the DEP profile with a typed API (`POST /v1/dep/profiles/{name}`: URL, skipped panes, await-configuration, supervision, org details) rather than by hand through the proxy; it is checked and uploaded, and assigned. "Device assigned" events from DEP feed blueprints (a new serial is placed in its groups before it first checks in) and pre-license apps by serial.

### Listing devices, enrollments and the queue

`GET /v1/devices`, `/v1/enrollments`, `/v1/enrollments/{id}`, `/v1/enrollments/{id}/queue`, `/v1/queue`: filters by platform, enrollment type, group, state, serial; opaque keyset cursors (`limit`, `cursor`, `next`), so a page never skips or repeats rows while the fleet changes. Results never include sealed data.

### Device workflows

Under `/v1/devices/{id}`: `lost-mode` (POST, DELETE, GET; supervised iOS, refused on User Enrollment), `locate`, `play-sound`, `activation-lock/bypass-code` (POST, DELETE), `filevault/rotate`, `recovery-lock`, `firmware-password`, `secrets`, `apps`. What a device sends back that must stay secret (bypass codes, FileVault recovery keys, recovery lock passwords) is decrypted where needed (FileVault rotation uses a one-use certificate and a PKCS#7 reply), sealed with the tenant key, and shown only by `POST secrets/{kind}/reveal`, which writes an audit row (`secrets/audit`). Bootstrap tokens are escrowed and served back to the device.

### Apps and Apps and Books (VPP)

`PUT /v1/vpp/tokens/{name}` stores a content token per tenant (sealed). Licensing uses the v2 REST API: `GET /v1/vpp/{name}/assets`, `/assignments`, `POST assign` and `unassign` (device-based, so no Apple Account is needed; Apple answers asynchronously and the result is read from its events). A blueprint **app** item names an App Store id (`ResolveApp` looks it up by id or bundle id) and gets: license assignment, then `InstallApplication` (or `InstallEnterpriseApplication` for manifests), managed app configuration and attributes, `RemoveApplication` on leaving scope, and a declarative `app.managed` declaration where the device takes it (iOS 17.2, macOS 26). Installed apps are refreshed with `InstalledApplicationList` and shown at `GET /v1/devices/{id}/apps`.

### Network and mobile users (UserAuthenticate)

For a Mac bound to a directory, or a Shared iPad, the device asks the server to authenticate the person who logs in (`UserAuthenticate`), and then sends an `AuthToken` on everything that user's channel does. Turn it on with `-ua-realm` and a way to check people; without it users are declined, as before.

- The server answers the first request with an HTTP digest challenge (`Digest nonce="…",realm="…"`; each nonce is good once, for five minutes, for that enrollment) and checks the digest in the second against **a stored hash or a bridge, never a password**. `fleetcore ua-hash -user kim -realm corp` reads a password from standard input and prints a `user:realm:ha1` line for the `-ua-users` file (`ha1` is `MD5(user:realm:password)`). Or point `-ua-verify-url` at a service next to your directory (Open Directory, LDAP, an identity provider) that holds the password: it receives the digest fields as JSON with a bearer secret and answers `{"ok": true}`.
- A right digest returns an `AuthToken` (stored hashed, replaced at the user's next login); a wrong one returns 200 with an empty token, as Apple specifies. The digest is the standard RFC 2617 form, computed over the HTTP method the check-in could use; Apple does not publish the method and URI, so the check accepts PUT, POST and GET.
- User-channel requests (`TokenUpdate`, command results) must carry the token once the user has one; with `-ua-require-token`, a user who never completed the handshake is refused. Device-channel requests are untouched.

### Events

fleetcore turns database changes into events and keeps them for seven days in a log with sequence numbers. 24 types cover enrollments, devices (enrolled, OS changed, renamed, supervision, groups and tags, deactivated, Lost Mode), commands (queued, result), blueprint item states on devices, blueprints and groups, vault access, DEP assignment, new OS releases, schema updates and applicability changes (`GET /v1/events/types`). Events carry identifiers and states, never profile bodies, results, tokens or anything sealed.

Ways to receive them:

- **Poll or stream the log:** `GET /v1/events?after=<seq>&types=command.*` and `GET /v1/events/stream` (Server-Sent Events, resumable with `Last-Event-ID`).
- **Subscriptions:** `POST /v1/event-subscriptions` registers a webhook. Each subscription has its own cursor and is delivered to one event at a time in order, signed (`X-Fleetcore-Signature: sha256=…`, HMAC over `timestamp.body` with a secret shown once), retried with backoff, paused by itself after 25 failures in a row, and replayable from any sequence number. A slow endpoint holds back only itself. URLs must be https and cannot point at private addresses (checked again on connection, so DNS tricks and redirects do not get through).
- **Sinks:** `-relay-nats nats://…` publishes `<prefix>.<type>.<key>` (default prefix `fleetcore.events`; `nq.events` joins the platform's bus), core or JetStream with `-relay-jetstream`; `-relay-webhook` posts to one URL. `-relay-types command.*,device.*` limits both.

At least once, in order, per tenant; `id` is stable for repeats. One process per tenant relays at a time (a lease in the database). The change stream needs a replica set, and a MongoDB identity restricted to its database must be allowed to open a change stream there.

### Metrics

`/metrics` serves Prometheus text: HTTP by route, MDM messages by type, pushes, reconcile runs, event deliveries, and, read from MongoDB at most every 15 seconds, enrollments, devices by platform, OS version and how current their OS is, devices not seen, the reconcile and command queues with the age of the oldest waiting item, blueprint applications by kind, delivery and state, vault access, identity certificates and when each certificate and token the server depends on (CA, APNs, DEP, Apps and Books) expires, the event log and every subscription's lag, Apple's feeds and MongoDB. Scrape it with a bearer token (`-metrics-token`) or the management login; `deploy/fleetcore/prometheus-rules.yaml` has alerting rules. The full list is in [api-reference.md](api-reference.md#metrics).

### Moving from another MDM

- **From a NanoMDM-family server** (NanoMDM on file, MySQL, PostgreSQL or a key-value store): enrollments move without the devices doing anything. Start fleetcore with `-migration` (and `-migrate-ca old-scep-ca.pem` so the identity certificates the old server issued are accepted while the fleet moves), run `nano2nano -storage … -storage-dsn … -url https://fleetcore/v1/migration -key KEY` against the old storage, and move the DNS name or the old server's MDM address. The enrollments arrive as the check-ins the old server stored, with their push tokens and topic, so the same push certificate must be uploaded. Remove `-migration` and `-migrate-ca` when done.
- **From anything else** a device cannot be moved in place (its enrollment belongs to the old server's push certificate and identity), so it enrolls again; what can move is what you know about it. `POST /v1/devices/import` takes a CSV from the old product (`Content-Type: text/csv`; the serial number, name, user, groups and tags columns are recognized by common names, or named with `columns=serial:Serial Number,name:Computer Name`) or JSON `{"devices":[{"serial","name","groups","tags"}]}`, and records for each serial number what to do when it enrolls here (name, static groups, tags), and does it at once for any device that already has. Unknown groups are an error for their row, or are created with `create_groups=true`. `GET /v1/devices/expected` lists the records.

### Hardware-bound identity (ACME) and Platform SSO

`-acme` serves RFC 8555 at `/acme` with Apple's `device-attest-01`: the device proves with its Secure Enclave that the key is in hardware, from a genuine Apple device (the attestation chain is verified to the Apple Enterprise Attestation Root, the freshness nonce is the hash of the key authorization, and the serial and UDID come from the certificate). The CSR must carry the attested key. By default only serials that Business Manager assigned to this tenant may get a certificate (`-acme-allow-unassigned` opens it to any genuine Apple device). With `-acme-for-enrollment`, enrollment profiles ask for the identity by ACME instead of SCEP (iOS 16, macOS 13.1).

A **platform_sso** blueprint item configures the extensible single sign-on extension: a vendor preset (Microsoft Entra ships as data; add others the same way) plus your overrides, checked against Apple's `com.apple.extensiblesso` schema. It is delivered as the `extensible-sso` declaration where the device takes it (macOS 27) and as a profile otherwise; Presets ship for Microsoft Entra, Okta (give it your org's `domain`) and PingID Desktop; each is data in `sso_presets.json`, with the extension and team identifiers vendors publish, and nothing stops you adding another. Platform SSO exists on macOS only.

### Translating profiles to declarations

`POST /v1/ddm/translate` takes a profile and returns, for each payload, the declaration(s) that replace it. Keys match through an alias table (`fleetcore/ddm/translate_aliases.json`, for renamed, nested and restructured settings: passcode, software update, mail, Exchange, CalDAV and CardDAV, LDAP, Google, subscribed calendars, DNS, restrictions) and then by name; nested dictionaries and arrays are translated key by key; every value is checked against the declaration's schema (type, allowed values, range) and a value that does not fit is reported, not sent. A payload that several declarations replace (restrictions are split across Siri, intelligence, keyboard and accessibility) comes back as several results. Certificates (`pem`, `root`, `pkcs1`) become an asset (the bytes as `application/pem` or `application/pkcs1`) and PKCS#12 identities an identity asset (a JSON document with the PKCS#12 data and its password, as Apple defines it), each plus a configuration that refers to it; the result lists the `assets`, and `items` ready to put in a blueprint (asset items and declaration items); give `blueprint` and `apply: true` and they are added to that blueprint and saved (asset documents are checked against Apple's credential schemas when any blueprint is saved), and other payloads that point at a certificate by `PayloadCertificateUUID` (DNS, mail, Exchange, VPN) are rewritten to refer to the same asset. User names and passwords in accounts, VPNs, proxies and content filters become user name and password credential assets that the declaration refers to; the password is in the asset document, which the server hosts behind the device's identity and seals at rest, and never in the declaration. SCEP and ACME payloads become a credential asset whose data is the JSON document Apple defines for them (`com.apple.credential.scep` and `.acme`, now part of the pinned schemas and checked key by key, including required keys and allowed values); the SCEP challenge, if the payload has one, is stored in that document, which the server hosts behind the device's identity and seals at rest. IKEv2, IPsec and custom (plug-in) VPN payloads translate into their VPN declarations (booleans stored as 0 and 1 become booleans, nested network, idle, on-demand, DNS and proxy settings are restructured, algorithms the declaration no longer allows are reported); L2TP, PPTP, always-on and transparent proxy VPNs are reported. Web content filters translate when they are plug-in filters. The restrictions payload is translated wherever Apple's own key descriptions point at a declaration (Siri, Apple Intelligence, external intelligence, keyboard, app allow and deny lists, software update deferrals and Background Security Improvements), and every other restriction stays in a profile. Nothing secret goes into a declaration itself: they are reported with the reason (they belong in an asset). `GET /v1/ddm/translate/coverage` lists, per payload type, the keys translated, the keys with a documented reason not to, and the keys nobody has looked at yet, which is the list to read after a schema update. A test fails the build if an alias points at a key Apple's schema no longer has.

## Tenants, instances and the shared database

An instance is one fleetcore process serving one tenant. Several tenants' instances can share one MongoDB cluster. There are two layouts, and the difference is what the *cluster* enforces:

| Layout | Database | What keeps tenants apart | If one tenant's server is compromised |
| --- | --- | --- | --- |
| **Dedicated** | one database per tenant (`-db fleetcore_acme`, no `-tenant`) | MongoDB: the server's certificate user can use only its database | the attacker can use that database and no other; the cluster refuses the rest |
| **Shared** | one database for many tenants (`-tenant acme`), every document carries the tenant | the software, and each tenant's own encryption key | the attacker holds the connection to the shared database, so it can in principle read other tenants' unencrypted metadata (device serials, names); it cannot open their secrets |

MongoDB grants access per database, never per document, so the second layout cannot be enforced by the cluster; this is why it is built so that nothing secret is readable without the tenant's key (below), and why a tenant that needs the cluster to enforce the boundary is given the first layout. A source check (`fleetcore/tenantlint`) fails the build if any query on a shared collection is not scoped to its tenant, or any write is not stamped with it.

### Why not a MongoDB proxy

A proxy that rewrites every query to add the tenant would give the shared layout the cluster-level boundary it lacks, and it is the first thing worth asking about. It is not built, on purpose:

- MongoDB has no row-level access control, and no mature open-source proxy adds it. Envoy's MongoDB filter only observes and injects faults; `mongos` routes shards; per-document rules exist only in Atlas services.
- A rewriting proxy has to understand every command that can touch data: `find`, `aggregate` with `$lookup`, `$unionWith`, `$graphLookup`, `$out` and `$merge`, update pipelines, `findAndModify`, bulk writes, transactions, change streams, cursors. Anything it misses is a cross-tenant read, and it has to keep up with every MongoDB release. That is a security product to maintain, and it would hold every tenant's data behind one component.
- The alternative that is a real boundary, a gateway that offers typed operations instead of queries and takes the tenant from the caller's certificate, means turning the whole storage layer into an RPC service. It is the right move if tenants ever need to be dense *and* cluster-enforced; it is not needed while a dedicated database per tenant is available for those who need enforcement.

What is done instead, in three independent layers: the cluster enforces the boundary where it can (a database and a certificate user per tenant); cryptography enforces it where it cannot (secrets sealed under a key only the tenant's server holds); and the software's own scoping is checked two ways, so it does not depend on every future change remembering it: a source check (`tenantlint`) that fails if a query on a shared collection is not scoped or a write not stamped, and a runtime check that watches every command sent to MongoDB while the tests run (the whole server, the NanoMDM storage suite and the blueprint suite run as one tenant of a shared database) and fails on any command that would read or write across tenants, including filters built at run time. For field-level protection beyond that, MongoDB's client-side field encryption can sit on top of the sealing described below.

## How a tenant's server proves itself to the cluster

No passwords. The server authenticates to MongoDB with a client certificate (MONGODB-X509 over TLS), and the cluster maps the certificate's subject to a user that may use one database:

```sh
fleetcore mongo-user -uri 'mongodb://mongo:27017/?replicaSet=rs0&authSource=$external' \
    -cert admin.pem -ca ca.pem \
    -subject 'CN=acme-mdm-1,O=tenants' -db fleetcore_acme
```

The role it creates can find, insert, update, remove, create indexes and collections and read statistics in that database. It cannot drop anything, create users, or touch another database; a read-only identity (`-read-only`) is available for reporting. `-script` prints the equivalent `mongosh` commands for an operator who runs them by hand. The server then starts with `FLEETCORE_MONGO_CERT` and `FLEETCORE_MONGO_CA`. The certificate's organization must differ from the cluster members' (MongoDB refuses a client that could pass for one). To rotate a server's certificate, issue a new one with the same subject; to remove a tenant's access, `mongo-user -remove`.

This is tested against a real TLS, key-file, x509 `mongod` (`FLEETCORE_X509_TEST=1 go test ./fleetcore/provision`): the identity works in its own database (including the transactions the MDM needs), is refused another tenant's database, cannot administer, a connection without the certificate or without TLS gets nothing, a certificate from another CA is turned away, and removing the user removes the access.

Cloud MongoDB offers other passwordless logins (AWS IAM, OIDC workload identity); they work through the connection string and need nothing from fleetcore.

## Secrets at rest

What is sealed: queued commands (profiles carry Wi-Fi passwords and account credentials), command results (they can carry recovery keys), TokenUpdate messages (they carry the unlock token), bootstrap tokens, push certificate keys, ADE OAuth tokens and token-exchange keys, blueprint items and their history, declaration payloads, and the data behind assets and legacy profiles. SCEP challenges are stored only as hashes. The CA key is sealed with its passphrase.

How: AES-256-GCM with a key per tenant and the tenant and field bound into each value, so a sealed value moved to another tenant or another field does not open. Tenant keys are derived from a master key (HKDF), so nothing per tenant needs storing:

```sh
fleetcore keygen                                  # the master key: keep it offline
fleetcore tenant-key -tenant acme -master-key-file master.keys    # prints <key id>:<base64>
```

Give each tenant's server only its tenant key (`FLEETCORE_TENANT_KEYS`). The master key then never sits on a tenant's server, and a compromised server can open its own tenant's data and no one else's. A single-tenant installation can use the master key directly or just a passphrase.

Sealing turns off the readable BSON copies of commands, results and token updates (they would hold the same secrets), so those can no longer be queried in the database.

**Turning it on for existing data**: set the key, restart, run `fleetcore -rekey`. Values written before are still read meanwhile.
**Rotating**: generate a new master key; run `tenant-key` with the new key first and the old one second; give servers both versions; restart; run `fleetcore -rekey` until it reports nothing changed; then remove the old key.

## Reaching an instance's management API

Everything under `/v1` is the management API. For an operator or a control plane the strongest login is a client certificate: `-admin-ca ca.pem` makes the API require a certificate chaining to that CA (the server must end TLS itself), with no shared secret to leak. An API key can be required as well; with both, both must be right. Keys are compared in constant time and every call is logged with who made it (the certificate's subject, or "api key"). Devices never use this API: they authenticate with the certificate SCEP gave them, and they can download only what was prepared for them.

| Path | |
| --- | --- |
| `/v1/commands` | JSON command API (types, send, results) |
| `/v1/blueprints`, `/v1/groups`, `/v1/devices`, `/v1/enrollments`, `/v1/queue` | desired state, groups, inventory, enrollments and the command queue (cursors), device workflows |
| `/v1/vpp` | Apps and Books tokens, assets and licenses |
| `/v1/dep` | Automated Device Enrollment |
| `/v1/ddm` | declarative management: support matrix, coverage, per-device state, profile translator |
| `/v1/applicability` | which payloads apply to which platforms |
| `/v1/schemas`, `/v1/os-releases` | Apple's definitions and releases in use |
| `/v1/push`, `/v1/enqueue`, `/v1/pushcert` | NanoMDM's own API |

## A secure cluster, from nothing

`deploy/fleetcore/make-certs.sh` makes a CA and the certificates with openssl, and `compose.secure.yaml` is the shape of the result. On the first start of a cluster that requires a key file and TLS, MongoDB lets you (from localhost, before any user exists) initiate the replica set and create a root user; create it, then create each tenant's identity with `mongo-user`. Use your own PKI in production, short-lived certificates where you can, and keep the CA key off the servers.

## Operating

- **Back up** MongoDB; the master key separately and offline. Without the key, sealed data cannot be recovered.
- **Several processes** of one tenant can run at once: devices and API calls can reach any, and the work queue (blueprint reconciliation) is shared through leases in the database.
- **Apple's feeds** (device-management schemas on GitHub, the releases feed, GDMF) need outbound HTTPS; `-no-feeds` uses the snapshot built into the binary. Schemas refresh daily and releases hourly, with no restart.
