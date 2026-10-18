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

### Declarative device management (built)

`fleetcore/ddm` serves Apple's protocol (tokens, declaration-items, declarations, status) from MongoDB for every device, so any server process can answer any device. Declarations are not stored by hand: the blueprint engine computes each device's whole set (the blueprints whose scope matches it, plus the status subscription every device gets), writes only the difference, and sends a `DeclarativeManagement` command (carrying the tokens, so a device that is current skips a round trip) only when the set's token changed. A device leaving a scope loses the declaration and its activation the same way. Status reports bring back whether each declaration is active and valid, which becomes the application state (`applied`, `failed` with Apple's reason), and update the inventory (OS version, model, serial) without polling.

Blueprint item kinds for it:

- **declaration**: any configuration type from Apple's schema (`com.apple.configuration.passcode.settings`, accounts, VPN, certificates...), validated against the schema when the blueprint is saved, with the activation generated for you.
- **os_update**: software update enforcement (`softwareupdate.enforcement.specific`). The target comes from Apple's GDMF service, which Apple names as the source for enforcement targets: `latest` is the newest release the device's *hardware* is listed for (an iPhone Apple stops at 26 is moved to 26.7.1, not left failing on 27), `latest-in-major` stays in the device's own major version, or a fixed version. The deadline is `deadline_days` (default 7) after the release was published, or after the item last changed if later, at `deadline_hour` local time. Only what GDMF currently offers is ever targeted, as Apple requires; the enforcement is lifted when the device reports the new version.
- **profile** with `delivery` `auto` (the default): see below.
- **asset** and management declarations: see below.

Who can receive what is read from Apple's schema per declaration type: the platform, the OS version it was introduced in, and the enrollment kinds it allows (supervised, user, device). A device that cannot is not failed; its application is `not_applicable` with the reason. Supervision is learned from the device (`IsSupervised`), because Apple allows many declarations, including software update enforcement on a Mac, only on supervised devices.

### Minimum OS versions (from Apple's schemas; `GET /v1/ddm/support`)

| Platform | Declarative management (status channel, activations) | Profiles as declarations | Software update enforcement | Update settings | Update status items |
| --- | --- | --- | --- | --- | --- |
| iOS and iPadOS | 15.0 | 15.0 | 17.0 (supervised or device enrollment) | 18.0 | 17.0 |
| macOS | 13.0 | 13.0 | 14.0 (supervised only) | 15.0 (supervised only) | 14.0 |
| tvOS | 16.0 | 16.0 | 18.4 | 18.4 | 18.4 |
| visionOS | 1.1 | 1.1 | 26.0 | 26.0 | 26.0 |
| watchOS | 10.0 | 10.0 | none | none | none |

The MDM software-update commands are deprecated in 26 and removed in 27, so below the enforcement version a device is updated with `ScheduleOSUpdate` (an `os_update` item falls back to it, honoring `install_action`, only where the schema says the command exists and the device is supervised if it requires that), and from 27 on only declaratively. The per-platform list of every declaration type with its first version and enrollments is `GET /v1/ddm/support?platform=macOS`. A regression test pins these numbers to the schema.

### Declarative management: what is built beyond the basics

- **Assets**: `asset` items. With `asset_data` the server hosts the bytes (credentials, certificates, any data) at `/ddm/asset/{key}` behind the device's identity, and writes the asset's `Reference` itself, with the URL, size and SHA-256 the device checks. Assets whose values live in the declaration (SCEP, ACME, user identity) take them from `declaration`. A configuration refers to an asset by writing `$asset:<item id>`; it is resolved to the identifier the asset has on the device, checked when the blueprint is saved, and a configuration whose asset does not apply to a device is itself not applicable there.
- **Legacy profiles as assets**: from OS 27 (where the schema has `ProfileAssetReference`) a profile is delivered as a data asset the device verifies by size and hash; before that, by URL.
- **Management declarations**: server capabilities and organization info are sent to every device that takes them. A property declaration carries what the server knows that the device does not (its tags and groups), so on-device activation predicates can use them. A `declaration` item may also be any management declaration type.
- **Activation predicates**: a `declaration` item's `predicate` goes into its activation, for conditions only the device knows. Scope (the blueprint's rule) is still decided on the server first.
- **User channel**: `scope: user` sends a declaration to each user channel of the device (a macOS user, a Shared iPad user), tracked per user. The schema decides what can go where: for example the CalDAV account on macOS is user-channel only, and the engine says so instead of sending it to the system channel. A user who checks out loses their declarations at once. Status reports from a user channel update that user's record.
- **Status subscriptions per blueprint**: `status_items` adds status items to what devices in scope report, filtered by the schema for the device's platform, version and enrollment (so passcode compliance is requested on iOS and not on macOS, where it does not exist).
- **Translating profiles**: `POST /v1/ddm/translate` expresses a profile as native declarations where Apple has an equivalent. Keys match through a table for settings Apple renamed (passcode policy is covered) and by name ignoring case and punctuation; anything else is returned as untranslated, never guessed, and approximate matches say so.

Still open, and honest about it:

- Secrets in assets (passwords, identity data) are stored as given in the blueprint and in the download store. Encrypting them per tenant is part of the hardening list.
- The translator covers the common payloads, certificates, identities, SCEP and ACME (as assets), and the IKEv2, IPsec and plug-in VPNs (see the coverage report). Not covered: L2TP, PPTP, always-on and transparent proxy VPNs, the TCC privacy payload (its mapping into app privacy defaults is not described in the schemas), built-in content filters, and the restrictions Apple has not given a declaration yet.
- Apple has no ordering between declarations beyond references and activations, so there is none here.
- Nothing has been tried on real devices: the protocol is tested against Apple's schema and the documented behavior.

### Retiring profiles

What the schemas say (not what is commonly assumed): declarative management is not new in 27. The status channel and legacy-profile declarations start at iOS 15 and macOS 13, and most native configurations at iOS 17 and macOS 14. What 27 adds is deprecation of profile payloads that now have declarations (DNS settings and proxy, relay, passcode policy, the new restrictions payload and content caching), the removal of the software-update commands, and `ProfileAssetReference` for legacy profiles. `InstallProfile` itself is not deprecated. And on macOS, most declaration types allow only supervised, user and local enrollments, so a Mac enrolled by hand (not through Apple Business Manager) cannot take them.

So the plan is a delivery planner, not a switch:

1. A profile item's `delivery` is `auto`: on a device that takes declarative management (platform, OS version and enrollment all allowed for the legacy-profile declaration), the profile, already adapted to the platform, is stored for the device and delivered as a **legacy-profile declaration**; the device downloads it with its device identity from `/ddm/profile/{key}` and the status channel reports it. Every other device keeps the `InstallProfile` command. `profile` forces the command, `declarative` refuses to downgrade and says why.
2. A profile already installed by command is **removed before** the declaration takes over when a device becomes capable (for example supervised through Business Manager), so the two never fight.
3. Native declarations (`declaration` items) are the end state. `GET /v1/ddm/coverage` lists each profile in the blueprints with its payload types, the native declaration that replaces each where one exists (`fleetcore/ddm/equivalents.json`, checked against the schema in tests), where Apple deprecated or removed the payload, and how much of the fleet is on each delivery. Translating a profile's keys into the matching declaration is a manual step for now.

Smart groups and scoping are unchanged and are the point of putting this in blueprints: scope is evaluated on the server (indexed rules over device attributes, dynamic and static groups, OS-currency tests), and that decides which declarations are in a device's set. Apple's own on-device activation predicates remain available as a declaration payload for conditions only the device knows (`Predicate`).

### Compared with KMFDDM

[KMFDDM](https://github.com/jessepeterson/kmfddm) (Jesse Peterson, an experimental companion to NanoMDM on SQL) is a good model of the protocol: server tokens as content hashes, a declarations token composed per enrollment, automatic notification, a stored status channel. fleetcore does the same, with differences that follow from being one product: declarations are not assigned to devices by hand (the README says you maintain which sets go to which enrollment IDs, and that an assignment lasts until removed); the device set is computed from scope rules, so nothing is left behind when a device leaves a group or checks out, and a change notifies only devices whose set actually changed (KMFDDM says it may over-notify); and declarations are validated against Apple's current schema when saved.

### What the schemas told us about Apple's direction

In the current schema, the MDM software-update commands (`ScheduleOSUpdate`, `AvailableOSUpdates`, `OSUpdateStatus`, `ScheduleOSUpdateScan`) are deprecated in OS 26 and removed in OS 27. Enforcing updates therefore needs **declarative device management** (software update enforcement configurations and the status channel). fleetcore refuses the removed commands for devices on 27 and says so. DDM is the next phase and the next piece of this roadmap.

### Apple feature coverage

| Area | State |
| --- | --- |
| MDM protocol, check-in, push (APNs), command queue | built (NanoMDM) |
| SCEP identity, enrollment profile, TLS | built |
| ADE (Automated Device Enrollment) | built: tokens, sync, assigner, devices, typed profile definition (skipped panes), signed device request (no challenge for a known device), await configuration, device-assigned events into blueprints |
| Commands and responses | built: JSON API over all of Apple's commands, validated against the current schema |
| Configuration profiles per platform | built (applicability) |
| Blueprints, groups, staged rollout, drift repair | built |
| OS currency and update enforcement | feed and out-of-date rules built; enforcement needs DDM |
| Declarative device management: configurations, activations, status channel, software update enforcement, legacy-profile delivery | built; assets (credentials, data) and management properties are not yet blueprint items |
| Apps: VPP / Apps and Books licensing, `InstallApplication`, managed app config | built: device-based licensing, app items, `app.managed` declaration, installed-app inventory |
| User Enrollment and Account-Driven enrollment (Managed Apple Accounts, BYOD) | built: discovery, OIDC sign-in, `GetToken`, enrollment-type rules from the schemas; `UserAuthenticate` is minimal |
| Managed Device Attestation (ACME), Platform SSO | built: ACME `device-attest-01` server and enrollment option; Platform SSO as a blueprint item (macOS) |
| Lost Mode, Activation Lock bypass, Rotate FileVault key, Bootstrap token, Recovery lock | built as workflows with a sealed, audited secret vault |
| Content caching, extensions, certificates | commands available |
| Supervision and channel awareness (device vs user channel) | used by the engine: supervision, enrollment type and channel decide what is sent |

## Remaining

Everything in the earlier plan is built. What is left, honestly:

1. **Real devices**: the protocol, ADE, BYOD, attestation, VPP, Platform SSO, UserAuthenticate and the translator's output are tested against Apple's schemas, documented behavior and fakes (including a synthetic attestation chain). None has run against a real device, Business Manager, an Open Directory or the App Store yet. UserAuthenticate in particular: Apple does not publish the HTTP method and URI of the digest, so the check accepts several.
2. **Translator**: always-on VPN, TCC privacy (the schemas do not describe the mapping), and the restrictions Apple has not given a declaration yet (the coverage report lists them). Content types and the shared-secret credential form are chosen from Apple's schemas and unverified on a device.
3. **Migration**: in-place migration works from NanoMDM-family servers. Other MDMs cannot move enrollments (they belong to the old push certificate and identity); their device lists import, but there is no reader for any product's API, only CSV and JSON.
4. **Platform SSO presets** for vendors other than Entra, Okta and PingID (Jamf Connect's identifiers were not found in a source to trust).
5. **Event relay**: no event for every change; add types in `fleetcore/relay` as consumers need them.
