# fleetcore

fleetcore is an Apple MDM in one binary, built on NanoMDM and MongoDB: the MDM protocol, a SCEP certificate authority, enrollment profiles, TLS, Automated Device Enrollment, a JSON command API, blueprints (desired state with groups and staged rollouts), declarative device management, software update enforcement, and platform-aware profiles. It follows Apple's published definitions as they change. It stands alone: it needs a MongoDB replica set, an Apple push certificate and a public HTTPS name, and nothing else. Any product can manage it through its HTTP API.

What is in the roadmap and what is not yet built is in [fleetcore-roadmap.md](fleetcore-roadmap.md).

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

Then upload the push certificate and key (`PUT /v1/pushcert`), and send a device to `https://mdm.example.com/enroll`. Without Docker: `make fleetcore` builds the binary.

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
| `FLEETCORE_API_KEY` | `-api-key` | management API key (basic auth, user `fleetcore`) |
| `FLEETCORE_ADMIN_CA` | `-admin-ca` | management API requires a client certificate from this CA |
| `FLEETCORE_MONGO_CERT`, `FLEETCORE_MONGO_CA` | `-mongo-cert`, `-mongo-ca` | log in to MongoDB with a certificate |
| `FLEETCORE_TENANT_KEYS` | `-tenant-keys` | this tenant's encryption keys |
| `FLEETCORE_MASTER_KEY`, `FLEETCORE_MASTER_KEY_FILE` | `-master-key` | master keys (for a single-tenant server, or an operator) |
| `FLEETCORE_NO_FEEDS` | `-no-feeds` | do not contact Apple's schema, release and GDMF feeds |

Subcommands for operators: `fleetcore keygen`, `fleetcore tenant-key`, `fleetcore mongo-user`. `fleetcore -rekey` seals everything stored with the current key and exits.

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
| `/v1/blueprints`, `/v1/groups`, `/v1/devices` | desired state, groups, inventory |
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
