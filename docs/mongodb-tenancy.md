# MongoDB backend: tenant layouts, measurements, and what to run

The mongodb storage backend can hold a tenant in two ways. Both are the same code; the difference is one option.

| | Database per tenant | Shared collections (`WithTenant(id)`) |
| --- | --- | --- |
| How | `WithDatabase("t_acme")`; the whole database is one tenant's | one database; every document has `t`, every index leads with it, `_id` is `tenant + id`, the store is bound to its tenant when made |
| New tenant | create a database and its indexes (about 42 ms) | bind a store (about 0.5 ms, no schema work) |
| What a tenant costs the server | about 28 files and about 3 MB of memory each, even empty | nothing per tenant; it grows with data only |
| Separation | strongest in the database itself (its own namespace; a database user can be limited to it) | enforced by the store (see below) and by tests |
| Leaving | drop the database | `DeleteTenant` (deletes by tenant in each collection) |

## Measurements

`tools/tenantbench` (go run ./tools/tenantbench -pg ... -mongo ...) runs the same storage calls against PostgreSQL 16 and MongoDB 8, backends alternating within each test so drift lands on all alike. These runs were on one laptop with both databases in Docker (7.7 GB VM), 16 workers, 60 tenants of 1,000 devices (60,000 devices, 228,000 storage calls). Treat run-to-run noise as roughly 20 to 30 percent; the ratios below held across five runs, the absolute numbers will not on other hardware.

| | PostgreSQL | Mongo, database per tenant | Mongo, shared |
| --- | --- | --- | --- |
| New tenant | 13 ms (schema in a shared database), 29 to 34 ms (own database) | 42 to 47 ms | 0.5 ms |
| Check-in (TokenUpdate) | 4,700 ops/s, p99 9.6 ms | 4,900, p99 7.5 | 5,000, p99 8.7 |
| Fetch next command | 9,600 ops/s, p99 9.0 ms | 12,200, p99 3.3 | 11,200, p99 3.7 |
| Acknowledge a command | 3,900 ops/s | 3,000 | 2,600 |
| Queue a command for 100 devices | 1,600 ops/s | 750 | 800 |
| On disk, same data | 1,589 MB | 776 MB | 715 MB |

- Shared collections cost nothing in speed against a database per tenant at this size.
- Mongo is faster at reading what a device asks for next and has a tighter tail; PostgreSQL is faster at the two heaviest writes (acknowledging, and queueing for many devices at once: Mongo does that in a transaction).
- Mongo stores the same data in about half the space, with the raw XML and a queryable copy of every plist.
- **Database per tenant does not scale in one mongod.** At 1,800 tenant databases (about 50,000 open files, 108,000 data handles) the server held 5.7 GB resident, and at about 2,000 it was killed for memory in the 7.7 GB VM (`OOMKilled`). Plan on a few hundred databases per server, not thousands. (Cluster-level guidance from MongoDB is to stay well under about 10,000 collections; this schema uses about 7 collections and 12 indexes per tenant.)

## What to run

1. **Default: shared collections, one replica set per "cell".** Tenants are assigned to a cell (a replica set); a cell holds as many as its data volume and write rate allow, not as many as its object count allows. Provisioning is a registry row.
2. **Dedicated tier: a database per tenant** for tenants that need hard isolation (a contract, a regulator), a few hundred per server at most, or a cluster of their own. Same backend, no `WithTenant`.
3. **Keep PostgreSQL** where write-heavy MDM traffic dominates and the tenant count is modest (schema per tenant gives 13 ms provisioning); it is the stock NanoMDM path.

## Separation and security in shared mode

- The tenant is fixed when the store is made. No method takes a tenant; there is no way to point a store at another's data.
- Every read and write goes through three helpers: `pk` (an `_id` that carries the tenant), `scope` (the tenant in every filter) and `stamp` (the tenant on every write). Indexes lead with the tenant, so a query without one would not even be fast.
- Tests (`go test ./storage/mongodb`, `NANOMDM_MONGODB_STORAGE_TEST_URI`): the shared end-to-end suite passes per tenant with the same device ids and command uuids in both (no collision), every method is checked from another tenant (push info, next command, certificate hashes, tally, clear queue, disable, enqueue), deleting one tenant leaves the other whole, and every document has a tenant.
- Not done yet, and worth doing before customers share a cell: per-tenant encryption of the secrets (push certificate keys, unlock and bootstrap tokens, identity certificates) under a key per tenant, so a mistake that crosses tenants yields ciphertext; separate database users per cell (never the cluster admin); an audit that the service user has no access beyond its database; and a lint or review rule that no code reaches a collection except through the helpers.
- Events: one cluster-level change stream (or a few, partitioned by a hash of the tenant) feeding NATS, not a stream per tenant. See the discussion in the Fleet repository's NATS notes.
