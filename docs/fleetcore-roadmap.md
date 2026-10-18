# fleetcore: one binary, a whole MDM

`cmd/fleetcore` runs everything NanoMDM leaves out in one process, on one MongoDB. This page says what exists and how each remaining piece will be built.

## Built (phase 1)

| NanoMDM leaves out | fleetcore |
| --- | --- |
| SCEP | `fleetcore/pki`: a CA made on first start (key sealed with scrypt + AES-GCM), SCEP at `/scep`, one-use challenges stored in MongoDB |
| TLS | `-tls-cert/-tls-key`, or `-autocert host` (Let's Encrypt), or TLS ended by a proxy with `-cert-source signature` or `header` |
| Enrollment (profiles) | `fleetcore/enroll`: `/enroll` returns a profile with the SCEP and MDM payloads and a fresh challenge; `EnrollAuthorize` gates it |
| Enrollment (device) API | the check-in endpoints plus identity checks (certificate must chain to this CA and match the UDID) |
| MDM + API | NanoMDM service and `/v1` unchanged, on the MongoDB storage |

Covered by `fleetcore/server/server_test.go`: profile, SCEP (reused and wrong challenges refused), mTLS check-in, command delivery and acknowledgement, foreign certificates refused.

| ADE (DEP) API access | `fleetcore/dep`: NanoDEP's storage on MongoDB (secrets sealed with the CA passphrase; passes NanoDEP's own storage test suite, also tenant-shared), its API under `/v1/dep`, one syncer and assigner per DEP name started when tokens are stored, devices recorded in `dep_devices` |

### Using ADE

All under `/v1/dep` with the API key (user `fleetcore`):

1. `GET tokenpki/{name}`: returns a certificate to upload to Apple Business Manager (your MDM server entry).
2. Download the server token from ABM, then `PUT tokenpki/{name}` with the token file: stores the OAuth tokens and starts syncing.
3. `PUT config/{name}` only for a non-default DEP base URL (tests).
4. Define a profile through `ANY proxy/{name}/profile` (Apple's `POST /profile`, with `url` set to `{base}/enroll`), then `PUT assigner/{name}` with its UUID: new devices get it.
5. `GET devices/{name}` lists what the syncer has seen; `POST sync/{name}` syncs now.

Covered by `fleetcore/dep` tests (conformance suite; a fake DEP service for fetch, sync and removal).

| JSON command API | `fleetcore/commands`: Apple's 67 MDM commands (generated from apple/device-management by `go run ./tools/gencommands`), validation with per-key errors, plist built for you, results read back as JSON |

### Using the JSON command API

With the API key, under `/v1/commands`:

- `GET types`, `GET types/{RequestType}`: the commands and each one's schema (keys, types, allowed values, OS support).
- `POST /` with `{"request_type":"DeviceLock","params":{"Message":"Call IT"},"devices":["UDID"],"platform":"macOS"}`: checks the params (unknown keys, missing required keys, wrong types, values outside Apple's allowed lists, keys or commands that do not exist on the platform) and answers 422 with a list of `problems` (path and message) if wrong. Otherwise builds the plist, queues it for each device and pushes (`"no_push":true` to skip). Data is base64, dates RFC 3339. Commands that lose data or lock someone out (EraseDevice, DeviceLock, RemoveProfile and others) need `"confirm":true`.
- `GET {uuid}`: per device, `Queued` or the device's status and its response as JSON.

Arrays follow Apple's schema where it describes one element type; the Settings command's alternative shapes are checked only as objects.

## Planned

1. **ADE follow-ups**: an ADE enrollment path that skips the one-use challenge when the device is known from DEP (serial match), and device-assigned events for blueprints.
2. **VPP**: a client for the Apple Business `vpp/v1` API (tokens per tenant, assets, assignments, licenses) with `InstallApplication` commands built from assignments.
3. **Blueprints**: documents (profiles, commands, apps, scope by group/serial/platform) applied at enrollment and re-applied when they change. Port the scope and policy logic from Fleet; stored as native documents.
4. **JSON command API**: `POST /v1/commands` takes JSON, validates against the Apple device-management schemas (port `schemas.ts` as generated Go types), turns it into a plist command and enqueues it.
5. **Device and enrollment REST APIs**: list/filter devices, enrollments, queue and results over the native BSON documents, with cursors.
6. **Hardening**: per-tenant encryption of push key, unlock and bootstrap tokens, and identity keys; per-cell database users; a relay from one cluster-level change stream (or outbox) to NATS for events.

Order: JSON command API, blueprints, VPP, device APIs, hardening. ADE and the command API are what make a first real fleet usable.
