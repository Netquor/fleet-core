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

| Blueprints | `fleetcore/blueprints`: a reconciler (see below), native groups, staged rollouts, revision history |
| Platform-aware profiles | `fleetcore/applicability`: payloads and keys a platform or OS version does not support are left out, from Apple's schemas plus editable overrides |
| Day-one Apple support | `fleetcore/schemas` follows apple/device-management at runtime; `fleetcore/osreleases` follows Apple's releases feed |

### Blueprints

A blueprint is a scope (a rule), a list of items (profiles and commands), and optionally rings for a staged rollout. The engine is a reconciler, the same shape as a Kubernetes controller:

1. A check-in (Authenticate, TokenUpdate, a DeviceInformation answer), a blueprint or group change, a new Apple release, or the drift timer (6 hours) marks a device due (`reconcile_at`).
2. Workers claim due devices with a lease (`findOneAndUpdate`), so any number of server processes share the queue with no coordinator, and a crashed worker's devices come back when its lease ends.
3. For each device the engine works out what it should have (blueprints whose scope matches, the highest priority winning when two blueprints put the same profile on it), compares that with what was sent and confirmed (`bp_applied`), and queues only the difference. Items carry a content hash, so editing a profile reinstalls exactly that profile.
4. Command results move each application through pending, applied, failed (retried with backoff, five attempts) or removing. A device that leaves the scope has the profile removed unless the blueprint says `keep_on_leave`.
5. Rings (`percent`, `after_seconds`) hold a change back for part of the fleet. A device's place is a stable hash of blueprint and device, so the same devices are always the canaries.

Scope rules are data (`{"all":[{"field":"platform","op":"eq","value":"macOS"},{"field":"os_version","op":"gte","value":"14.0"}]}`) and compile to MongoDB filters, so "which devices does this hit" is an indexed query. Groups are static (devices are put in them) or dynamic (a rule); a rule can name groups, and a dynamic group can name others. `os_version` accepts `latest` (newest release for the device's platform) and `latest-in-major` (newest release of the device's own major version, which is the right test for a Mac that cannot move up), so "devices that are out of date" is a rule: `{"field":"os_version","op":"lt","value":"latest-in-major"}`.

### Platform applicability

A profile is written once and scoped to a mixed fleet. Before it is sent, the engine asks `applicability` what the device's platform and OS version can use: Apple's schema for the payload type and for each key (down into dictionaries), plus overrides for what Apple's schemas cannot know. An override is a row (`com.google.Chrome*` is macOS only), edited at `/v1/applicability`; a few ship as data (Chrome, Edge, Firefox) and can be changed or removed, nothing is hard-coded. A payload type nobody knows is kept. What was left out is recorded on the application (`note`), and a profile with nothing left is `not_applicable`, not a failure. Payloads and keys Apple has removed by the device's OS version are left out too; commands removed by that version are refused with a message saying so.

### Staying current with Apple

- **Schemas**: `schemas.Refresher` checks Apple's `release` branch daily, downloads and parses it, refuses a snapshot that lost most definitions, saves it in MongoDB, and switches to it without a restart. Validation, the command API and applicability all read the current set. `go run ./tools/genschemas` refreshes the copy built into the binary. `POST /v1/schemas/refresh` forces a check.
- **OS releases**: Apple's public releases feed is read hourly; betas and release candidates are ignored; the newest shipping release is kept per platform and per major version. A new release re-evaluates every device.

### What the schemas told us about Apple's direction

In the current schema, the MDM software-update commands (`ScheduleOSUpdate`, `AvailableOSUpdates`, `OSUpdateStatus`, `ScheduleOSUpdateScan`) are deprecated in OS 26 and removed in OS 27. Enforcing updates therefore needs **declarative device management** (software update enforcement configurations and the status channel). fleetcore refuses the removed commands for devices on 27 and says so. DDM is the next phase and the next piece of this roadmap.

### Apple feature coverage

| Area | State |
| --- | --- |
| MDM protocol, check-in, push (APNs), command queue | built (NanoMDM) |
| SCEP identity, enrollment profile, TLS | built |
| ADE (Automated Device Enrollment) | built: tokens, sync, assigner, devices; follow-up: await-configuration flow, skip-pane profiles through the proxy |
| Commands and responses | built: JSON API over all of Apple's commands, validated against the current schema |
| Configuration profiles per platform | built (applicability) |
| Blueprints, groups, staged rollout, drift repair | built |
| OS currency and update enforcement | feed and out-of-date rules built; enforcement needs DDM |
| **Declarative device management** (configurations, assets, activations, management properties, status channel) | **next**: the check-in hook exists in NanoMDM; fleetcore needs the declaration store, the manifest and item endpoints, activation logic and status reports |
| Apps: VPP / Apps and Books licensing, `InstallApplication`, managed app config | planned |
| User Enrollment and Account-Driven enrollment (Managed Apple Accounts, BYOD) | planned: `GetToken`, UserAuthenticate, the enrollment-type rules in the schemas (`user_enrollment: forbidden`) |
| Managed Device Attestation (ACME), Platform SSO | planned |
| Lost Mode, Activation Lock bypass, Rotate FileVault key, Bootstrap token, Recovery lock | commands are available through the API; no workflows |
| Content caching, extensions, certificates | commands available |
| Supervision and channel awareness (device vs user channel) | recorded in the schemas; the engine does not yet use `supervised` or `user_enrollment` to decide |

## Planned

1. **ADE follow-ups**: an ADE enrollment path that skips the one-use challenge when the device is known from DEP (serial match), and device-assigned events for blueprints.
2. **VPP**: a client for the Apple Business `vpp/v1` API (tokens per tenant, assets, assignments, licenses) with `InstallApplication` commands built from assignments.
3. **Declarative device management**: declarations as blueprint items, with software update enforcement; status-driven drift detection.
4. **JSON command API**: `POST /v1/commands` takes JSON, validates against the Apple device-management schemas (port `schemas.ts` as generated Go types), turns it into a plist command and enqueues it.
5. **Device and enrollment REST APIs**: list/filter devices, enrollments, queue and results over the native BSON documents, with cursors.
6. **Hardening**: per-tenant encryption of push key, unlock and bootstrap tokens, and identity keys; per-cell database users; a relay from one cluster-level change stream (or outbox) to NATS for events.

Order: DDM, VPP and apps, user enrollment, device APIs, hardening, blueprints, VPP, device APIs, hardening. ADE and the command API are what make a first real fleet usable.
