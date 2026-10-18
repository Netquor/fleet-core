# fleetcore API reference

Every HTTP endpoint fleetcore serves and every request it makes to a system you run. For how to run and configure it see [fleetcore.md](fleetcore.md); for what is built and what is not see [fleetcore-roadmap.md](fleetcore-roadmap.md). The NanoMDM API that fleetcore mounts (`/v1/push`, `/v1/enqueue`, `/v1/pushcert`...) is also described by [openapi.yaml](openapi.yaml).

Written from the code (`fleetcore/server/server.go` and the packages it mounts) and checked against it; no endpoint here was exercised against real devices. Paths are relative to the public base URL.

## Contents

- [Authentication and conventions](#authentication-and-conventions)
  - [Management API authentication](#management-api-authentication)
  - [Device authentication (`CertSource`)](#device-authentication-certsource)
  - [Conventions](#conventions)
- [Enrollment, device endpoints and ADE](#enrollment-device-endpoints-and-ade)
  - [Public and utility endpoints](#public-and-utility-endpoints)
  - [Enrollment profile endpoints](#enrollment-profile-endpoints)
  - [SCEP](#scep)
  - [MDM check-in and command endpoints](#mdm-check-in-and-command-endpoints)
  - [Declarative management](#declarative-management)
  - [ACME (device attestation)](#acme-device-attestation)
  - [DEP management API (`/v1/dep`)](#dep-management-api-v1dep)
  - [Other MDM-adjacent behavior worth knowing](#other-mdm-adjacent-behavior-worth-knowing)
- [Blueprints, groups, devices and Apple definitions](#blueprints-groups-devices-and-apple-definitions)
  - [Scope rules](#scope-rules)
  - [Devices](#devices)
  - [Device import and expected devices](#device-import-and-expected-devices)
  - [DEP devices](#dep-devices)
  - [Groups](#groups)
  - [Blueprints](#blueprints)
  - [Applicability](#applicability)
  - [Apple schemas](#apple-schemas)
  - [Declarative management (DDM)](#declarative-management-ddm)
  - [OS releases](#os-releases)
- [Commands, listings, workflows, apps and NanoMDM's API](#commands-listings-workflows-apps-and-nanomdms-api)
  - [JSON command API](#json-command-api)
  - [Listings](#listings)
  - [Device workflows](#device-workflows)
  - [Apps and Books (VPP)](#apps-and-books-vpp)
  - [Migration](#migration)
  - [NanoMDM's own API](#nanomdms-own-api)
- [Events and subscriptions](#events-and-subscriptions)
  - [The event](#the-event)
  - [Subscriptions](#subscriptions)
- [Metrics](#metrics)
- [What fleetcore calls: events and bridges](#what-fleetcore-calls-events-and-bridges)
  - [Event sinks (`-relay-nats`, `-relay-webhook`)](#event-sinks--relay-nats--relay-webhook)
  - [MicroMDM-compatible webhook (embedding only)](#micromdm-compatible-webhook-embedding-only)
  - [UserAuthenticate bridge (`-ua-verify-url`)](#userauthenticate-bridge--ua-verify-url)
  - [Apple services fleetcore calls](#apple-services-fleetcore-calls)
- [Behaviors worth knowing](#behaviors-worth-knowing)

## Authentication and conventions

All paths below are relative to the server's public base URL (`-url`, for example `https://mdm.example.com`). Everything is served by one HTTP handler (`fleetcore/server/server.go`). Three families of endpoint exist, each with its own authentication:

| Family | Paths | Caller | Authentication |
|---|---|---|---|
| Management API | `/v1/...` (this file: `/v1/dep/...`) | operators, a control plane | `adminAuth`: API key and/or admin client certificate (below) |
| MDM protocol | `/mdm`, `/checkin`, `/ddm/profile/`, `/ddm/asset/` | enrolled devices | the device identity certificate, carried per `CertSource` (below) |
| Enrollment and public | `/enroll`, `/enroll/ade`, `/enroll/byod`, `/.well-known/com.apple.remotemanagement`, `/scep`, `/acme/...`, `/ca.pem`, `/healthz`, `/version` | people, devices not yet enrolled, monitors | per endpoint (none, Apple-signed request, OIDC bearer token, ACME JWS, SCEP challenge) |

### Management API authentication

The management API is mounted only when the server has an API key (`-api-key` / `FLEETCORE_API_KEY`) or an admin CA (`-admin-ca` / `FLEETCORE_ADMIN_CA`). With neither, every `/v1/...` path (including `/v1/dep/...`) and `/enroll/ade` is absent and answers 404.

| Configured | Requirement | Failure |
|---|---|---|
| API key only | HTTP Basic auth. The password must equal the API key (constant-time compare). The user name is ignored; the password is matched against `-api-key` and against every key in `-api-keys` (`name:key,name:key`). A call is logged and audited under the name of the key it used (`api key` for `-api-key`, `key <name>` for a named one), so give each person or system its own key. | `401`, `WWW-Authenticate: Basic realm="fleetcore"`, body `unauthorized` |
| `-admin-ca` only | A TLS client certificate that chains to the admin CA, with the client-auth extended key usage. | `401` `a client certificate is required` (none presented, or the request did not arrive over TLS) or `401` `the client certificate is not accepted` |
| Both | Both are required: the certificate check runs first, then the key check. | as above |

Notes:

- `-admin-ca` requires the server to terminate TLS itself (`-tls-cert`/`-tls-key` or `-autocert`); the certificate is read from the connection. The TLS listener asks for a client certificate but does not demand one at the handshake (`tls.RequestClientCert`), so browsers, SCEP clients and enrollment pages are not turned away.
- Every call is logged with who made it: the certificate subject, or `api key`. A control plane may send `X-Actor: <person>`; the log then reads `<who> (<person>)`. The header is only honored when an identity was established, and it is not itself authenticated.
- The authenticated identity is carried in the request context (`admin.Who`) and used by other endpoints to record who revealed a recovery key, wiped a device, and so on.

```sh
# API key
curl -u fleetcore:$API_KEY https://mdm.example.com/v1/dep/names
# admin CA (mutual TLS); add -u as well when both are configured
curl --cert admin.pem --key admin.key https://mdm.example.com/v1/dep/names
# naming the person a control plane acts for
curl -u fleetcore:$API_KEY -H 'X-Actor: alice@example.com' https://mdm.example.com/v1/dep/names
```

### Device authentication (`CertSource`)

The MDM endpoints (`/mdm`, `/checkin`, `/ddm/profile/`, `/ddm/asset/`) identify the device by the identity certificate it received at enrollment (from SCEP or ACME). `-cert-source` / `FLEETCORE_CERT_SOURCE` chooses how that certificate reaches the handlers.

| `CertSource` | Where the certificate comes from | When to use | Enrollment profile |
|---|---|---|---|
| `tls` | The TLS client certificate (`r.TLS.PeerCertificates[0]`). This server terminates TLS. | Direct exposure, no CDN or proxy in front. | `SignMessage` false |
| `signature` | The `Mdm-Signature` header: a base64 CMS detached signature of the request body made by the device with its identity key; the certificate is taken from the signature. A failed verification answers `400`. A request with no `Mdm-Signature` carries no certificate. | TLS ends in front of the server (a CDN or proxy that does not forward the client certificate). | `SignMessage` true |
| `header` | A header named by `-cert-header`: either an RFC 9440 value (`:base64-DER:`, recognized by a leading colon) or a URL-query-escaped PEM (nginx `$ssl_client_escaped_cert`). An unparsable or empty header carries no certificate. | A trusted proxy verifies TLS and forwards the certificate. | `SignMessage` false |

Both `cmd/fleetcore` and `server.Config` default `-cert-source` to `tls`. `header` requires `-cert-header` or startup fails.

After extraction, `CertVerifyMiddleware` verifies the certificate against the device-identity CA (plus `-migrate-ca` CAs while migrating) with client-auth key usage. A missing or invalid certificate answers `400` (never `401`, deliberately: a 401 can make a device unenroll). Then the `certauth` service ties the certificate hash to the enrollment ID on the first `Authenticate` check-in and rejects a different certificate for an existing enrollment (`Config.AllowRetroactive` lets a device that enrolled before certificates were checked be associated later; no CLI flag sets it). `/ddm/profile/` and `/ddm/asset/` additionally require the certificate to map to a known enrollment, else `400`.

Device identity for each endpoint family:

| Endpoint | Identity | Notes |
|---|---|---|
| `/mdm`, `/checkin` | certificate per `CertSource`, plus the `UDID`/`EnrollmentID` in the plist body | the certificate must match the enrollment |
| `/ddm/profile/`, `/ddm/asset/` | certificate per `CertSource` only (enrollment resolved from the certificate hash) | no body |
| `/enroll`, `/enroll/byod` | none (the person is authorized by `EnrollAuthorize` or an OIDC token) | |
| `/enroll/ade` | CMS signature by a device certificate chaining to Apple's root | |
| `/scep` | SCEP one-use challenge password in the CSR | |
| `/acme/...` | ACME JWS with the account key; the device is proven by Apple attestation | |

### Conventions

| Topic | Convention |
|---|---|
| Content type | Management API: request and response bodies are JSON (`Content-Type: application/json`). Device endpoints: XML property lists, `.mobileconfig` (`application/x-apple-aspen-config`), JSON (declarative management, ACME), PEM, as described per endpoint. |
| Error body (fleetcore handlers) | `{"error": "message"}` with a non-2xx status. Used by the blueprints, workflows, commands and DEP-profile handlers. |
| Error body (NanoDEP handlers under `/v1/dep`) | `{"error": "message"}` with status **500** for almost every failure (a missing resource is not a 404). A few failures use the plain-text status line (`Bad Request`, `Method Not Allowed`). |
| Error body (device, enrollment, `/scep`) | Plain text (`http.Error`), a short message or the standard status text. |
| Error body (ACME) | RFC 7807 `application/problem+json`: `{"type":"urn:ietf:params:acme:error:<kind>","detail":"...","status":N}` plus a fresh `Replay-Nonce`. |
| Check-in and command errors | Plain status text. A bad plist is `400`; any other failure is `500`; declarative-management errors carry the status chosen by the handler (`400`, `404`). |
| Bytes | Base64 in JSON (standard alphabet, padded) for fleetcore handlers that carry binary values; ACME uses unpadded base64url throughout (`attObj`, `csr`, JWS parts). In plists, `<data>` is base64 as usual. |
| Timestamps | RFC 3339 in UTC (for example `2026-10-18T14:03:00Z`) in fleetcore JSON. DEP OAuth token expiry (`access_token_expiry`) is RFC 3339 as well. |
| Pagination | There is no single convention. fleetcore history endpoints use `?limit=&cursor=` and return `{"<items>": [...], "next": "<cursor>"}` (for example `GET /v1/commands`). NanoDEP `GET /v1/dep/names` uses `?limit=&offset=` (offset-based only; a `cursor` is refused) and returns `{"dep_names":[...]}` (default limit 100). `GET /v1/dep/devices/{name}` is unpaginated and capped at 1000 rows. |
| Methods | The standard-library mux serves the exact paths listed; a wrong method gets `405` where the handler checks it (`/enroll`, `/v1/dep/sync/`, NanoDEP method muxes) and is otherwise ignored. |
| Tenancy | A server belongs to one tenant (`-tenant` only selects the storage layout). There is no tenant field in any request. |
| Secrets | Stored sealed with the tenant key (`-master-key`, `-tenant-keys`) or the CA passphrase; API responses described here return them in clear where stated. |

---

## Enrollment, device endpoints and ADE

### Public and utility endpoints

#### `GET /healthz`

| | |
|---|---|
| Caller | load balancers, monitors |
| Auth | none |
| Response | `200`, body `ok` (plain text) |

#### `GET /version`

| | |
|---|---|
| Caller | monitors, tooling |
| Auth | none |
| Response | `200`, `application/json`: `{"version":"<Config.Version>"}` |

```sh
curl https://mdm.example.com/version
```

#### `GET /ca.pem`

| | |
|---|---|
| Caller | operators and devices that need to trust the device-identity CA (for example to configure a proxy or a mutual-TLS front end) |
| Auth | none |
| Response | `200`, `application/x-pem-file`: the device-identity CA certificate; while migrating (`-migrate-ca`) the old CAs are appended |
| Errors | none |

```sh
curl -o ca.pem https://mdm.example.com/ca.pem
```

### Enrollment profile endpoints

**Who may download a profile.** `/enroll` is closed unless the server was started with `-enroll-secret CODE` (the code is given as `?code=CODE`, as a Bearer token, or as the Basic-auth password), `-enroll-auth-url URL` (a forward-auth gate: the request's headers go to the URL and a 2xx answer lets it through, so a proxy or an identity provider decides), or `-enroll-open` (anyone who can reach the server). With none of them the endpoint answers `403` and the server logs why at start-up. `/enroll/ade` and `/enroll/byod` authenticate the device or the person themselves and are not affected.

All profile endpoints build the same two-payload profile (`fleetcore/enroll/profile.go`): an identity payload and a `com.apple.mdm` payload. Every copy carries a fresh one-use SCEP challenge (valid 24 hours by default (`Config.ChallengeTTL`), stored only as a hash; used up on first successful use at `/scep`). Responses carry `Cache-Control: no-store`.

Profile contents:

| Payload | Key facts |
|---|---|
| `com.apple.security.scep` (identity) | `URL` = `<base>/scep`; `Challenge` = one-use password; subject `O=<organization>`, `CN=%HardwareUUID%` (BYOD: `ue-<random>`); RSA 2048; key usage 5; `Retries` 3, `RetryDelay` 10 |
| `com.apple.security.acme` (identity, instead of SCEP, only when ACME is configured with `ForEnrollment`) | `DirectoryURL` = `<base>/acme/directory`; `KeyType` `ECSECPrimeRandom`, `KeySize` 384, `HardwareBound` true, `Attest` true; no challenge |
| `com.apple.mdm` | `ServerURL` = `<base>/mdm`; `CheckInURL` = `<base>/checkin` only when `-separate-checkin` (`Config.SeparateCheckin`) is set; `Topic` = APNs topic; `SignMessage` true only for `CertSource=signature`; `AccessRights` 8191 (removed for BYOD); `CheckOutWhenRemoved` true; `ServerCapabilities`: `com.apple.mdm.per-user-connections`, `com.apple.mdm.bootstraptoken`, `com.apple.mdm.token`; BYOD adds `EnrollmentMode` `BYOD` and `AssignedManagedAppleID` |

If the profile is under-configured (no topic, identifier, server or SCEP URL) the endpoint answers `503` with the reason.

#### `GET|POST /enroll`

| | |
|---|---|
| Purpose | Download the enrollment profile for a manually enrolled device (user-approved MDM). |
| Caller | a person or a script on the device (browser, `profiles` tool); the link can be shared because each download gets its own one-use challenge. |
| Auth | none by default. `Config.EnrollAuthorize`, if an embedding program sets it, is called with the request; an error becomes `403` with the error text. `cmd/fleetcore` does not set it, so the stock binary serves profiles to anyone who can reach the URL; put the access policy (code, invite, session) in front of it. |
| Request | no parameters, no body |
| Response | `200`, `application/x-apple-aspen-config`, `Content-Disposition: attachment; filename="enroll.mobileconfig"`, body an XML plist profile |

| Status | Meaning |
|---|---|
| 200 | profile |
| 403 | `EnrollAuthorize` refused (body is its message) |
| 405 | method other than GET or POST |
| 500 | `could not make a challenge` |
| 503 | the profile cannot be built (configuration incomplete) |

```sh
curl -o enroll.mobileconfig https://mdm.example.com/enroll
```

#### `POST /enroll/ade`

| | |
|---|---|
| Purpose | Serve the enrollment profile to a device Apple assigned to this server (Automated Device Enrollment), with no code or sign-in. |
| Caller | a device in Setup Assistant. The DEP profile's `url` points here (default `<base>/enroll/ade`, set from `Service.EnrollURL`, see `POST /v1/dep/profiles/{name}`). |
| Mounted | only when the management API is enabled (API key or admin CA configured). |
| Auth | The request body is a PKCS#7 (CMS) signed message made with the device's Apple-issued certificate. The server verifies the signature, requires exactly one signer, and verifies the signer's chain against Apple's root (`Config.ADERoots`, default the embedded Apple Root CA) at the current time. Then the serial number must be in the list of devices the DEP syncer recorded for this server. |
| Request | Signed CMS whose content is an XML plist: `SERIAL` (string, required), `UDID`, `PRODUCT`, `VERSION`. Body limit 1 MiB. HTTP method is not checked (devices POST). |
| Response | `200`, `application/x-apple-aspen-config`, `Cache-Control: no-store`, the profile with a fresh one-use SCEP challenge. |

| Status | Meaning |
|---|---|
| 400 | empty body (`a signed request is expected`), not CMS (`not a signed request`), or no serial in the plist (`the request names no device`) |
| 401 | signature does not verify, not exactly one signer, or the signer certificate does not chain to Apple |
| 403 | `this device is not assigned to this server` (serial not among the recorded DEP devices) |
| 500 | serial lookup failed, or the challenge could not be made |
| 503 | the profile cannot be built |

Surprise: the serial must already be in the local device list, which the syncer fills (every `Interval`, default 30 minutes, or `POST /v1/dep/sync/{name}`); a device Apple assigned minutes ago may be refused until the next sync.

#### `GET|POST /enroll/byod`

| | |
|---|---|
| Purpose | Account-driven User Enrollment: return an enrollment profile for the person who is signed in with a Managed Apple Account. |
| Caller | an iPhone, iPad or Mac, after it read the discovery document below. |
| Mounted | only when BYOD is configured (`-byod-issuer`, `-byod-jwks`, `-byod-audience`, optionally `-byod-claim` default `email`, `-byod-login-url`). |
| Auth | `Authorization: Bearer <JWT>` issued by the configured OpenID Connect provider. The JWT is validated: signature (RS256 or ES256 by default, key by `kid` from the JWKS, cached 15 minutes, refetched at most every 30 seconds), issuer, audience, and a required expiry. The claim named by `-byod-claim` (default `email`) must be present and is the Managed Apple Account. `sub` is recorded as the subject. |
| Response | `200`, `application/x-apple-aspen-config`: a User Enrollment profile (no `AccessRights`, `EnrollmentMode` `BYOD`, `AssignedManagedAppleID` set, identity certificate CN `ue-<16 random chars>`). The server records which person the certificate name belongs to (kept 7 days), so the enrollment can be tied to the person. |

| Status | Meaning |
|---|---|
| 401 | no token or an invalid one. Header `WWW-Authenticate: Bearer` or, when a login URL is configured, `Bearer method="apple-as-web" url="<login URL>"`; body `sign in required` |
| 500 | challenge could not be made, or the enrollment could not be recorded |
| 503 | the profile cannot be built |

#### `GET /.well-known/com.apple.remotemanagement`

| | |
|---|---|
| Purpose | Discovery document for account-driven enrollment. Apple devices read it from the Managed Apple Account's domain; the organization's web server for that domain serves it or redirects the path to this server. |
| Mounted | only when BYOD is configured. |
| Auth | none |
| Response | `200`, `application/json`: `{"Servers":[{"Version":"mdm-byod","BaseURL":"<base>/enroll/byod"}]}` |

### SCEP

#### `GET|POST /scep`

| | |
|---|---|
| Purpose | SCEP certificate authority that issues the device identity certificate. |
| Caller | the device, following the `com.apple.security.scep` payload of the enrollment profile. Not meant for people. |
| Implementation | the `micromdm/scep` server mounted at exactly `/scep` |
| Operations | `GET /scep?operation=GetCACaps`, `GET /scep?operation=GetCACert`, `GET /scep?operation=PKIOperation&message=<base64>`, `POST /scep?operation=PKIOperation` with the PKCS#7 message as the body |
| Auth | the CSR must carry a valid challenge password. The challenge is checked and consumed with `FindOneAndDelete` (live, one use). A missing, expired or already used challenge fails the PKIOperation with a SCEP failure response. |
| Issued certificate | signed by the server CA, validity `Config.SCEPValidityDays` (default 365; `-scep-validity-days`), client-auth usage; renewal within the validity window is not allowed (`WithAllowRenewalDays(0)`) |
| Response | per SCEP: `application/x-x509-ca-cert` or `application/x-x509-ca-ra-cert` for `GetCACert`, the capability list for `GetCACaps`, `application/x-pki-message` for `PKIOperation` |

Body limits, status codes and failure encoding come from the SCEP library; fleetcore adds none.

### MDM check-in and command endpoints

#### `POST /mdm`

| | |
|---|---|
| Purpose | The MDM server URL (`ServerURL`). One endpoint carries check-in messages and the command/result exchange unless `-separate-checkin` (`Config.SeparateCheckin`) is set. |
| Caller | an enrolled device (after APNs wakes it, or on its own for check-ins). |
| Auth | device identity certificate per `CertSource`, verified against the device CA (see conventions). Failures answer `400`. |
| Routing | A request whose `Content-Type` starts with `application/x-apple-aspen-mdm-checkin` is a check-in; anything else is a command exchange. |
| Request (check-in) | XML plist with `MessageType`: `Authenticate`, `TokenUpdate`, `CheckOut`, `UserAuthenticate`, `SetBootstrapToken`, `GetBootstrapToken`, `DeclarativeManagement`, `GetToken`, with `UDID`/`EnrollmentID` and, for user channels, `UserID`. Query-string parameters are passed to the service as request params. |
| Request (command exchange) | XML plist: `Status` (`Idle`, `Acknowledged`, `Error`, `CommandFormatError`, `NotNow`), `UDID` or `EnrollmentID`, and for results `CommandUUID` plus any result keys. |
| Response (check-in) | usually empty `200`; `GetBootstrapToken` returns a plist; `UserAuthenticate` returns a digest-challenge plist or an empty body; `GetToken` returns a `TokenData` plist (see below); `DeclarativeManagement` returns JSON (below). |
| Response (command exchange) | empty `200` when no command is queued, otherwise the next queued command as an XML plist. |

| Status | Meaning |
|---|---|
| 200 | handled |
| 400 | plist did not parse, or the certificate is missing, invalid or does not match the enrollment (the check is deliberately never a 401) |
| 500 | any other processing error |

Services chained per request: the NanoMDM service, the blueprint observer (inventory and results), an optional outbound webhook (`-webhook-url`, MicroMDM-style; `-relay-webhook` is the separate event relay), and the `certauth` guard. When user authentication is configured (`-ua-realm`), `TokenUpdate` and command results on the user channel are refused if the `AuthToken` check fails.

`GetToken` for service type `com.apple.maid` returns a Managed Apple Account JWT signed with the DEP name's token-exchange key (`-maid-dep` chooses the name; empty uses the only one, and with several names the request fails).

#### `POST /checkin`

Same handler family as `/mdm`, mounted only when `-separate-checkin` is set: `/checkin` takes check-in messages and `/mdm` takes command exchanges. The enrollment profile then carries `CheckInURL=<base>/checkin`. Authentication, statuses and bodies are as for `/mdm`.

### Declarative management

Declarative management has no URLs of its own. The device sends a check-in message `MessageType: DeclarativeManagement` to `/mdm` (or `/checkin`) with `Endpoint` (string) and `Data` (base64 in the plist, JSON bytes), and the server replies with the JSON the endpoint defines (`fleetcore/ddm/service.go`).

#### `DeclarativeManagement` with `Endpoint: tokens`

| | |
|---|---|
| Request | no `Data` needed |
| Response | `200` JSON: `{"SyncTokens":{"DeclarationsToken":"<token>","Timestamp":"<RFC 3339 UTC>"}}`. The token is the stored one, or the token of an empty set when none was synced. The timestamp is when the device's declaration state last changed (now, if never). |

#### `DeclarativeManagement` with `Endpoint: declaration-items`

| | |
|---|---|
| Request | no `Data` needed |
| Response | `200` JSON: `{"Declarations":{"Activations":[{"Identifier","ServerToken"}],"Assets":[...],"Configurations":[...],"Management":[...]},"DeclarationsToken":"<token>"}`. The group arrays are always present (possibly empty). `ServerToken` is the first 16 bytes (hex) of SHA-256 over kind, type, identifier and the payload as sorted JSON; `DeclarationsToken` is the first 16 bytes (hex) of SHA-256 over the sorted `kind/identifier/token` lines. |
| Side effect | records the token as synced for this device |

#### `DeclarativeManagement` with `Endpoint: declaration/<kind>/<identifier>`

| | |
|---|---|
| `<kind>` | `configuration`, `activation`, `asset` or `management` |
| Response | `200` JSON: `{"Type":"com.apple.configuration...","Identifier":"...","ServerToken":"...","Payload":{...}}` |
| Errors | `400` malformed endpoint (no identifier); `404` `no <kind> declaration "<identifier>"` (unknown, or stored under another kind) |

#### `DeclarativeManagement` with `Endpoint: status`

| | |
|---|---|
| Request | `Data` is the device's status report JSON: `{"StatusItems":{...},"Errors":[{"StatusItem","Reasons":[{"Code","Description","Details"}]}],"FullReport":bool}`. `management.declarations` holds `activations`, `configurations`, `assets` and `management` arrays of `{identifier, server-token, active, valid (unknown|invalid|valid), reasons}`. |
| Behavior | stores the latest state per declaration and the other status items, then calls the blueprint engine (inventory and blueprint state follow). Declaration identifiers and item names have `.` and `$` replaced in storage keys. |
| Response | `200`, empty body |
| Errors | `400` when `Data` is not valid JSON |

Any other `Endpoint` answers `400 unknown declarative management endpoint "<name>"`.

#### `GET /ddm/profile/<key>` and `GET /ddm/asset/<key>`

| | |
|---|---|
| Purpose | Download targets referenced by declarations: a legacy configuration profile (`/ddm/profile/`) or an asset's data (`/ddm/asset/`, content type `application/x-plist` for app-install assets). The blueprint engine writes the URL (`<base>/ddm/asset/<key>`) into the declaration. |
| Caller | the device's declarative management client. |
| Auth | device identity certificate per `CertSource`, and the certificate must map to an enrollment, else `400` (not `401`). |
| Key | the last path segment (`strings.LastIndex(path, "/")`), looked up in the stored data of that device. Both prefixes read the same store, so `/ddm/profile/x` and `/ddm/asset/x` return the same item. A device cannot read another device's data. |
| Response | `200` with the stored `Content-Type` (`application/x-apple-aspen-config` for profiles) and body. |

| Status | Meaning |
|---|---|
| 200 | data |
| 400 | no certificate, or the certificate is unknown |
| 404 | no data under that key for this device |
| 500 | storage error |

### ACME (device attestation)

Mounted at `/acme/` only when ACME is enabled (`-acme`). `-acme-for-enrollment` makes enrollment profiles use `<base>/acme/directory` instead of SCEP (iOS 16, iPadOS 16, macOS 13.1 or later). The certificate comes from the same CA as SCEP and is accepted exactly like a SCEP one (client auth, CN = first identifier value, validity `Config.SCEPValidityDays`, default 365).

Common rules (`fleetcore/acme/server.go`, `jws.go`):

| Rule | Detail |
|---|---|
| Method | every endpoint except `directory` and `new-nonce` is `POST` with a flattened JWS body (`protected`, `payload`, `signature`), body limit 1 MiB. There is no POST-as-GET: authz, order, challenge and cert are fetched with a signed POST (an empty payload `""` is allowed). |
| Algorithms | `ES256` (P-256), `ES384` (P-384), `RS256` (RSA at least 2048 bits). Anything else: `badSignatureAlgorithm`. |
| Protected header | `alg`, `nonce`, `url` required. `url` must equal `<base>/acme<path>` exactly. Exactly one of `jwk` (new-account only) or `kid` (all others; `kid` = the account URL `<base>/acme/account/<id>`). |
| Nonces | taken from the `Replay-Nonce` header of any previous response and spent once; they expire after 1 hour. Every response, success or error, carries a fresh `Replay-Nonce` and `Cache-Control: no-store`. |
| Errors | `application/problem+json`, see conventions. |
| Retention | orders and authorizations expire 7 days after creation; an order's `expires` is 24 hours. |
| Identifiers | `permanent-identifier` (the serial number) and `hardware-identifier` (the UDID); one to four per order. |

Authorization rule (`srv.Authorize`, `fleetcore/server/server.go`), applied to each identifier in `new-order` before anything is attested:

| `-acme-allow-unassigned` | Result |
|---|---|
| set | every identifier is accepted |
| not set | only a `permanent-identifier` whose serial number is in the recorded DEP device list is accepted (the device list the syncer keeps; requires the management API to be enabled, otherwise nothing is accepted). A `hardware-identifier` is always refused in this mode. A refusal answers `403 unauthorized` `this server does not issue to that device`. |

Surprise: with the default (unassigned devices not allowed), `hardware-identifier` orders are always refused, because only serial numbers are looked up.

The device-attest-01 flow:

1. `GET /acme/directory`, `HEAD`/`GET /acme/new-nonce`.
2. `POST /acme/new-account` (JWS with `jwk`).
3. `POST /acme/new-order` with the serial number (and optionally UDID).
4. For each authorization, `POST /acme/challenge/<id>` with `{"attObj":"<base64url CBOR>"}`. The server builds the key authorization `token + "." + account thumbprint` (RFC 7638 SHA-256, base64url), requires the attestation's freshness nonce (extension `1.2.840.113635.100.8.11.1`) to equal SHA-256 of it, verifies the `x5c` chain to Apple's Enterprise Attestation Root (`Config.ACME.Roots`), and reads the serial (`1.2.840.113635.100.8.9.1`) and UDID (`...9.2`) from the leaf. The attested device must match the identifier (case-insensitive). The attested public key is stored.
5. When every authorization is valid the order becomes `ready`.
6. `POST /acme/finalize/<id>` with `{"csr":"<base64url DER>"}`; the CSR's public key must equal the attested key of every authorization.
7. `POST /acme/cert/<id>` returns the PEM chain; the identity certificate is then used for MDM.

#### `GET /acme/directory`

| | |
|---|---|
| Auth | none |
| Response | `200` JSON `{"newNonce":"<base>/acme/new-nonce","newAccount":"<base>/acme/new-account","newOrder":"<base>/acme/new-order","meta":{"externalAccountRequired":false}}`, with `Replay-Nonce` |

#### `GET /acme/new-nonce`

| | |
|---|---|
| Auth | none |
| Response | `204`, header `Replay-Nonce`. (The handler does not check the method, so HEAD works too.) |

#### `POST /acme/new-account`

| | |
|---|---|
| Auth | JWS signed with the new account key, `jwk` in the protected header |
| Payload | `{"contact":["mailto:..."],"onlyReturnExisting":false}` (all optional; terms of service are not asked for) |
| Response | `201` for a new account, `200` for an existing one (same key thumbprint). Header `Location: <base>/acme/account/<id>`; body `{"status":"valid","contact":[...]}`. Note that `/acme/account/<id>` is only a `kid` namespace: no handler serves it (a GET there gets 404). |
| Errors | `400 accountDoesNotExist` when `onlyReturnExisting` is set and no account has the key; `400 badPublicKey`; `500 serverInternal` |

#### `POST /acme/new-order`

| | |
|---|---|
| Auth | JWS with `kid` |
| Payload | `{"identifiers":[{"type":"permanent-identifier","value":"C02XXXXXXXX"}]}`, one to four items |
| Response | `201`, `Location: <base>/acme/order/<id>`, body `{"status":"pending","expires":"<RFC 3339>","identifiers":[...],"authorizations":["<base>/acme/authz/<id>",...],"finalize":"<base>/acme/finalize/<id>"}` (`certificate` is added once issued) |
| Errors | `400 malformed` (no or more than four identifiers); `400 unsupportedIdentifier`; `403 unauthorized` (Authorize refused); `500 serverInternal` |

#### `POST /acme/authz/<id>`

| | |
|---|---|
| Auth | JWS with `kid`; the authorization must belong to the account |
| Response | `200` `{"status","identifier":{"type","value"},"expires","challenges":[{"type":"device-attest-01","url":"<base>/acme/challenge/<id>","token":"<random>","status"}]}` |
| Errors | `404 malformed` `no such authorization` |

#### `POST /acme/challenge/<id>` (the authorization id)

| | |
|---|---|
| Auth | JWS with `kid`; must belong to the account |
| Payload | `{"attObj":"<base64url of the CBOR attestation object>"}`; the object has `fmt: "apple"` and `attStmt.x5c` (at least two DER certificates, leaf first) |
| Response | `200` `{"type":"device-attest-01","status":"valid","url":"...","token":"..."}`. Repeating the request on an authorization that is already valid returns the same `valid` body. |
| Errors | `400 malformed` (authorization no longer pending or past expiry, `attObj` missing or not base64url); `403 unauthorized` (attestation invalid, wrong chain, wrong nonce, no device named, or it names another device than the order; the authorization is then marked `invalid` permanently); `404`; `500` |

#### `POST /acme/order/<id>`

| | |
|---|---|
| Auth | JWS with `kid`; must belong to the account |
| Response | `200` order object as for `new-order`. `status` is `pending`, `ready` or `valid`; `certificate` appears once valid. |
| Errors | `404 malformed` |

#### `POST /acme/finalize/<id>`

| | |
|---|---|
| Auth | JWS with `kid`; must belong to the account |
| Payload | `{"csr":"<base64url DER PKCS#10>"}` |
| Response | `200` order object with `status: "valid"` and `certificate: "<base>/acme/cert/<certid>"` |
| Errors | `403 orderNotReady` (not `ready` or past its 24-hour expiry); `400 badCSR` (missing, not base64url, unparsable, bad CSR signature, or a key other than the attested one); `404`; `500 serverInternal` |

#### `POST /acme/cert/<id>`

| | |
|---|---|
| Auth | JWS with `kid`; must belong to the account that ordered it |
| Response | `200`, `application/pem-certificate-chain`: the leaf, then the CA certificate(s) |
| Errors | `404 malformed` `no such certificate` |

---

### DEP management API (`/v1/dep`)

Mounted only when the management API is enabled. Every path is guarded by `adminAuth`. `{name}` is the DEP name: your label for one Apple Business Manager (or School Manager) server token. The name is the entire remaining path; it cannot contain `/`. All handlers except `profiles` and `devices`/`sync` are NanoDEP v0.7.0 handlers (`http/api`, `http/apinext`, `proxy`); their failures are JSON `{"error": "..."}` with status 500 unless noted.

Typical setup order:

1. `GET /v1/dep/tokenpki/{name}` returns a certificate; upload it to Apple Business Manager when adding the MDM server.
2. Download the encrypted server token (`.p7m`) from Apple and `PUT` it to `/v1/dep/tokenpki/{name}`; the OAuth tokens are decrypted and stored and the syncer for the name starts.
3. `POST /v1/dep/profiles/{name}` to define the profile and optionally make it the profile new devices get.

#### `GET /v1/dep/tokenpki/{name}`

| | |
|---|---|
| Purpose | Generate a new self-signed RSA key pair for the token exchange, store it as the staged pair, and return the certificate. Every call replaces the staged pair. |
| Query | `validity_days` (integer, default 1), `cn` (default `depserver`) |
| Response | `200`, `application/x-pem-file`, `Content-Disposition: attachment; filename="<name>.pem"`, the PEM certificate |
| Errors | `400` (plain text) empty name or non-integer `validity_days`; `500` JSON on key or storage failure |

```sh
curl -u fleetcore:$API_KEY -o abm.pem 'https://mdm.example.com/v1/dep/tokenpki/prod?validity_days=1'
```

#### `PUT /v1/dep/tokenpki/{name}`

| | |
|---|---|
| Purpose | Decrypt the server token Apple provided with the staged key, promote the staged pair to current, and store the OAuth tokens. Then (re)start the syncer for the name. |
| Query | `force=1` allows replacing tokens whose consumer key differs from the stored ones (default: refused to prevent an accidental overwrite) |
| Request | the raw `.p7m` file as the body |
| Response | `200` JSON, the stored tokens (see `PUT /tokens`, **including the secrets**) |
| Errors | `400` (plain text) empty name or invalid tokens; `500` JSON for no staged key (`GET` first), decryption failure, malformed tokens, storage failure, or `mismatched consumer key` |

```sh
curl -u fleetcore:$API_KEY -X PUT --data-binary @token.p7m 'https://mdm.example.com/v1/dep/tokenpki/prod'
```

#### `PUT /v1/dep/tokens/{name}`

| | |
|---|---|
| Purpose | Store OAuth 1 tokens directly (from a decrypted server token). Restarts the syncer for the name. |
| Query | `force=1` bypasses the consumer-key check |
| Request | JSON `{"consumer_key","consumer_secret","access_token","access_secret","access_token_expiry"}`; the four strings are required, the expiry is RFC 3339 |
| Response | `200` JSON, the tokens as stored |
| Errors | `400` plain text `Bad Request` when a string is empty; `500` JSON for bad JSON, `mismatched consumer key`, or storage failure |

#### `GET /v1/dep/tokens/{name}`

| | |
|---|---|
| Response | `200` JSON `{"name", "stored": true, "consumer_key_suffix": "…abcd", "access_token_expiry"}`. **The secrets are never returned**; to replace tokens, `PUT` new ones. |
| Errors | `404` when the name has no tokens |

#### `PUT /v1/dep/config/{name}` and `GET /v1/dep/config/{name}`

| | |
|---|---|
| Purpose | The Apple DEP API base URL used by the syncer and the proxy. When unset, `https://mdmenrollment.apple.com/` is used. |
| `PUT` request | JSON `{"base_url":"https://..."}`; `base_url` is required (replaces the whole config) |
| `PUT` response | `200` JSON, the config |
| `GET` response | `200` JSON `{"base_url":"..."}`, or `null` when nothing has been stored |
| Errors | `400` empty name; `500` JSON for bad JSON, `empty base URL`, storage failure |

Note: the proxy caches the parsed base URL per name for the life of the process, so a changed base URL is not picked up by the proxy until restart.

#### `PUT /v1/dep/assigner/{name}` and `GET /v1/dep/assigner/{name}`

| | |
|---|---|
| Purpose | The DEP profile UUID the assigner applies to newly seen devices of this name. (`POST /v1/dep/profiles/{name}` with `assign` sets it too.) |
| `PUT` query | `profile_uuid` (required) |
| Response | `200` JSON `{"profile_uuid":"<uuid>"}`; `GET` omits the field when none is set |
| Errors | `400` empty name or missing `profile_uuid`; `500` JSON on storage failure |

```sh
curl -u fleetcore:$API_KEY -X PUT 'https://mdm.example.com/v1/dep/assigner/prod?profile_uuid=ABCDEF0123456789'
```

#### `GET /v1/dep/names`

| | |
|---|---|
| Purpose | List DEP names that have a token-exchange key pair (that is, `GET /tokenpki/{name}` was called at least once). A name with only tokens stored through `PUT /tokens` and no key pair is not listed. |
| Query | `limit` (default 100), `offset`, `dep_name` (repeatable; filter to these names). `cursor` is refused. |
| Response | `200` JSON `{"dep_names":["prod","test"]}` sorted by name, indented with tabs |
| Errors | `400` JSON for a non-integer `limit` or `offset`; `500` JSON otherwise (including a `cursor`: `only offset-based pagination supported`) |

```sh
curl -u fleetcore:$API_KEY 'https://mdm.example.com/v1/dep/names?limit=20&offset=0'
```

#### `GET /v1/dep/devices/{name}`

| | |
|---|---|
| Purpose | The devices the syncer has recorded for the name (the same list that gates `/enroll/ade` and ACME). Each row is the device record as Apple returned it. |
| Pagination | none; at most 1000 rows, sorted by serial number |
| Response | `200` JSON `{"devices":[{"serial_number":"...","model":"...", ...}]}`; each element is Apple's device record as JSON (whatever fields Apple sent, for example `serial_number`, `model`, `os`, `device_assigned_date`) |
| Errors | `500` plain text on a storage error. Only GET is accepted. |

Rows are written on every sync; a device Apple removes (`op_type` `deleted`) is deleted from the list.

#### `POST /v1/dep/sync/{name}`

| | |
|---|---|
| Purpose | Ask the running syncer for the name to sync now (instead of waiting for its interval, default 30 minutes). The sync runs in the background. |
| Request | no body |
| Response | `202` empty body |
| Errors | `405` `POST only`; `404` `no syncer is running for that DEP name (store its tokens first)` |

After each fetch or sync the server records the devices, emits a blueprint device event, pre-licenses VPP apps to the serial of a new device, and applies the assigner profile (if set) to devices without a profile.

#### `POST /v1/dep/profiles/{name}`

| | |
|---|---|
| Purpose | Define a DEP profile with Apple (how an assigned device behaves in Setup Assistant), record what it promises, and optionally make it the profile new (and existing) devices get. `{name}` is the DEP name; the profile's own name is `name` in the body. |
| Request | JSON `ProfileSpec`, body limit 1 MiB. Unknown fields are ignored. |
| Response | `200` JSON `DefineResult` |
| Errors | `400` plain text `the body is not valid JSON: ...`; `422` JSON `{"error":"..."}` for a missing profile `name` or no enrollment URL (Apple is not asked); `502` JSON `{"error":"...","result":<DefineResult or null>}` for a failure calling Apple (`defining the profile: ...`), no profile UUID returned, a storage error, or a failure assigning existing devices (`result` then holds the progress so far) |

`ProfileSpec` fields (Go zero values apply for omitted fields, except where a default is listed):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | Profile name shown to Apple (`profile_name`). A missing value is a `422`. |
| `url` | string | this server's `<base>/enroll/ade` | Where the device fetches its enrollment profile. |
| `supervised` | bool | `true` | Device is supervised (`is_supervised`). Also stored as the promise used for devices Apple assigns to this name. |
| `mandatory` | bool | `true` | The person cannot skip enrollment (`is_mandatory`). |
| `removable` | bool | `false` | The person can remove the MDM profile (`is_mdm_removable`). |
| `await_configured` | bool | `true` | Hold the device in Setup Assistant until the server says it is configured (`await_device_configured`). Also stored as a promise. |
| `allow_pairing` | bool | `false` | Allow pairing with computers (`allow_pairing`). |
| `auto_advance` | bool | `false` | `auto_advance_setup`. |
| `multi_user` | bool | `false` | `is_multi_user` (Shared iPad). |
| `skip_setup_items` | string[] | none | Setup Assistant panes to skip. Names not in the built-in list (`KnownSetupPanes`, for example `Accessibility`, `AppleID`, `Biometric`, `Diagnostics`, `FileVault`, `Location`, `Passcode`, `Privacy`, `Siri`, `TOS`, `Welcome`, `Zoom`, ...) are still sent and reported in `unknown_panes`. |
| `department` | string | none | `department` shown on the device. |
| `support_phone` | string | none | `support_phone_number`. |
| `support_email` | string | none | `support_email_address`. |
| `org_magic` | string | none | `org_magic`. |
| `assign` | bool | `false` | Store the new profile UUID as the assigner profile so new devices get it. |
| `assign_existing` | bool | `false` | Also assign it to every recorded device of this name (in batches of 1000); implies `assign`. |

`DefineResult`:

| Field | Meaning |
|---|---|
| `profile_uuid` | UUID Apple returned |
| `unknown_panes` | submitted pane names not in the built-in list (omitted when empty) |
| `assigned` | devices Apple confirmed with `SUCCESS` (only with `assign_existing`; omitted when 0) |
| `not_assigned` | serial numbers Apple did not accept, sorted (omitted when empty) |

```sh
curl -u fleetcore:$API_KEY -X POST https://mdm.example.com/v1/dep/profiles/prod \
  -H 'Content-Type: application/json' \
  -d '{"name":"Corporate Mac","skip_setup_items":["AppleID","Siri","Privacy"],"department":"IT","support_phone":"+1 555 0100","assign":true,"assign_existing":true}'
```

Fields of Apple's profile that `ProfileSpec` does not expose (for example `configuration_web_url`, `devices`, `language`, `region`, `is_return_to_service`) can be set by calling Apple's `/profile` endpoint through the proxy below; doing so skips the local bookkeeping (supervised and awaiting promises, assigner profile).

#### `ANY /v1/dep/proxy/{name}/...`

| | |
|---|---|
| Purpose | Reverse proxy to Apple's DEP web service with the credentials of the DEP name: fleetcore manages the OAuth session, the proxy adds the token. Use it to call anything Apple offers (account detail, fetch/sync devices, device details, disown, assign/remove profile, define profile). |
| Request | `/v1/dep/proxy/prod/account` is forwarded as `/account` on the host in the name's `base_url` (default `https://mdmenrollment.apple.com/`); method, query and body pass through. The caller's `Authorization` header (the management credential) is removed before forwarding. |
| Response | Apple's response. |
| Errors | `404` when the name is empty; `502` when the upstream call fails, with the upstream auth error body when Apple rejected the credentials |

```sh
curl -u fleetcore:$API_KEY https://mdm.example.com/v1/dep/proxy/prod/account
curl -u fleetcore:$API_KEY -X POST https://mdm.example.com/v1/dep/proxy/prod/devices/disown \
  -d '{"devices":["C02XXXXXXXX"]}'
```

---

### Other MDM-adjacent behavior worth knowing

| Item | Detail |
|---|---|
| Migration endpoint | `POST /v1/migration` (check-in handler behind `adminAuth`, only with `-migration`) accepts `Authenticate`, `TokenUpdate` and `SetBootstrapToken` from another NanoMDM-family server without a certificate check. Documented in the management reference. |
| Management API routes outside this file | `/v1/enrollments`, `/v1/queue`, `/v1/commands`, the NanoMDM push and enqueue routes (`httpapi.HandleAPIv1`), `/v1/blueprints`, `/v1/groups`, `/v1/devices`, `/v1/applicability`, `/v1/schemas`, `/v1/os-releases`, `/v1/ddm/`, `/v1/vpp/`; all share the authentication above. |

## Blueprints, groups, devices and Apple definitions

Served by `fleetcore/blueprints/http.go` and mounted under `/v1`. All requests use HTTP basic auth (`-u fleetcore:$API_KEY`); the basic-auth user name is recorded as `updated_by` on blueprint saves. Bodies are JSON (`Content-Type: application/json`) except the CSV device import. Request bodies are limited to 32 MiB. Fields marked "base64" are Go `[]byte` values, so they travel as base64 strings.

Common conventions:

| Item | Behavior |
|---|---|
| Error body | `{"error": "message"}` |
| 400 | Body is not valid JSON (`the body is not valid JSON: ...`) or a required parameter is missing |
| 404 | `{"error":"not found"}` for an unknown blueprint, group or device |
| 422 | Validation failure |
| 500 | Store error |
| Timestamps | RFC 3339 |
| Pagination | Cursor based and sorted by id (devices) or serial (expected, DEP). Pass the previous page's `next` as the cursor; an empty `next` means no more pages. The cursor parameter is `cursor` everywhere (`GET /v1/devices/expected` still accepts the older `after`); `GET /v1/events` pages by sequence number (`after`) |

```sh
export API=https://fleet.example.com/v1   # your fleetcore base URL
```

### Scope rules

A blueprint's `scope`, a dynamic group's `rule`, and the `rule` of `POST /devices/query` share one JSON grammar (`Rule` in `rule.go`). An empty rule `{}` matches every device.

A rule is exactly one of: `all`, `any`, `not`, or a field test (`field` + `op` + `value`). Setting more than one is a 422 (`a rule is one of all, any, not or a field test`). Nesting deeper than 8 levels is rejected.

| Field | Type | Meaning |
|---|---|---|
| `all` | Rule[] | Every child matches (AND) |
| `any` | Rule[] | At least one child matches (OR) |
| `not` | Rule | Child does not match |
| `field` | string | Device attribute to test (below) |
| `op` | string | Comparison (below) |
| `value` | string, or string[] for `in`/`nin` | What to compare with |

Fields and the operators each accepts:

| `field` | Matches on | Ops | `value` |
|---|---|---|---|
| `platform` | Device platform (`macOS`, `iOS`, `iPadOS`, `tvOS`, `visionOS`, `watchOS`) | `eq`, `ne`, `prefix`, `in`, `nin` | string; list for `in`/`nin` |
| `model` | Model identifier | same | same |
| `serial` | Serial number | same | same |
| `name` | Device name | same | same |
| `dep_name` | Name of the ADE/DEP profile | same | same |
| `enroll_type` | Enrollment type string | same | same |
| `user` | Managed Apple Account (BYOD devices) | same | same |
| `tag` | Device tags (list membership) | `eq` (has), `ne` (does not have), `in` (has any of), `nin` (has none of) | string; list for `in`/`nin` |
| `group` | Group membership, by group id or name | `eq`, `ne`, `in`, `nin` | string; list for `in`/`nin` |
| `os_version` | OS version, compared numerically | `eq`, `ne`, `gte`, `gt`, `lte`, `lt` | version string such as `14.2` or `15.0.1`, or `latest`, or `latest-in-major` |

Rules for `value`: `eq`, `ne` and `prefix` need a string; `in` and `nin` need a list of strings. Anything else is a 422 such as `platform eq needs a string`, `platform does not support "gte"`, `unknown field "foo"`, or `"abc" is not a version (like 14.2 or 15.0.1)`.

Group references:

- `{"field":"group","op":"eq","value":"Engineering"}` matches by group id or by group name.
- A static group is a membership test on the device's `groups` list. A dynamic group (one with a `rule`) is replaced by its own rule, so groups can be defined in terms of other groups (nesting limit 8, otherwise `groups refer to each other too deeply`).
- `ne` and `nin` negate the whole expansion. An unknown group name is not an error; it matches no device (so `ne` on it matches every device).
- Group references are expanded when a blueprint is saved (a failure is `scope: ...`), when a device query runs, and at preview time.

`latest` and `latest-in-major` (only for `os_version`, from the Apple releases feed; see `/os-releases`):

| Value | Expands to |
|---|---|
| `latest` | For each platform, `platform eq P AND os_version <op> <newest release version of P>`; the alternatives are OR-ed. `os_version lt latest` therefore means "not on the newest release of its platform". |
| `latest-in-major` | For each platform and each major version M with a shipping release: `platform eq P AND os_version gte M.0 AND os_version lt M+1.0 AND os_version <op> <newest release in M>`. Meant for hardware that cannot move to the newest major. |
| No releases known | The rule matches nothing. |
| Releases feed unavailable | 422 `os_version "latest" needs the Apple releases feed, which is not available`. |

Example: Macs on macOS 14 or newer that are behind the newest release of their own major, and not tagged `lab`:

```json
{"all":[
  {"field":"platform","op":"eq","value":"macOS"},
  {"field":"os_version","op":"gte","value":"14.0"},
  {"field":"os_version","op":"lt","value":"latest-in-major"},
  {"not":{"field":"tag","op":"eq","value":"lab"}},
  {"any":[
    {"field":"group","op":"in","value":["Engineering","Design"]},
    {"field":"serial","op":"prefix","value":"C02"}
  ]}
]}
```

### Devices

#### Device object

Returned by the device endpoints (`id` is the enrollment ID). Omitted when empty.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Enrollment ID |
| `udid` | string | Device UDID |
| `serial` | string | Serial number |
| `name` | string | Device name |
| `managed_apple_id` | string | Managed Apple Account of a User Enrollment (BYOD) device |
| `platform` | string | `macOS`, `iOS`, `iPadOS`, `tvOS`, `visionOS`, `watchOS` |
| `model` | string | Model identifier |
| `os_version` | string | OS version |
| `dep_name` | string | ADE/DEP profile name |
| `enroll_type` | string | Enrollment type |
| `awaiting` | bool | In Setup Assistant waiting for the server to release it |
| `awaiting_since` | time | Since when it has been awaiting |
| `tags` | string[] | Tags |
| `groups` | string[] | Static group ids |
| `enrolled_at` | time | Enrollment time |
| `last_seen` | time | Last check-in |
| `active` | bool | Always present; false after unenroll |
| `apps` | AppInfo[] | Installed apps as last reported: `identifier`, `name`, `version`, `short_version`, `managed` |
| `apps_at` | time | When `apps` was reported |
| `lost_mode` | object | `enabled`, `message`, `phone`, `footnote`, `confirmed`, `since` |
| `location` | object | `latitude`, `longitude`, `altitude`, `horizontal_accuracy`, `at` |
| `users` | string[] | User-channel enrollment IDs (macOS users, Shared iPad) |
| `supervised` | bool or null | Learned from the device; absent until known |
| `os_checked_at` | time | When the OS version was last confirmed from the device |

#### GET /v1/devices

Lists devices, filtered. Every filter given must match (AND). Sorted by `id`.

Query parameters:

| Parameter | Meaning |
|---|---|
| `platform`, `model`, `serial`, `name`, `dep_name`, `enroll_type`, `user`, `tag`, `group` | Exact match (`eq`; for `tag` and `group` "has") |
| `os_version_lt` | Devices with `os_version` below this version (`latest` and `latest-in-major` accepted) |
| `cursor` | The previous page's `next` |
| `limit` | Page size, 1 to 1000; a value outside that range (or absent) becomes 100 |

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `devices` | Device[] | The page |
| `next` | string | Cursor for the next page; empty when the page was not full |

Errors: `422` invalid filter value or group expansion.

```sh
curl -u fleetcore:$API_KEY "$API/devices?platform=macOS&tag=lab&os_version_lt=15.0&limit=50"
```

#### POST /v1/devices/query

Lists devices matching an arbitrary scope rule.

Request body:

| Field | Type | Meaning |
|---|---|---|
| `rule` | Rule | See [Scope rules](#scope-rules); `{}` matches all |
| `after` | string | Cursor (device `id` of the last row of the previous page) |
| `limit` | int | Page size, 1 to 1000; otherwise 100 |

Response `200`: `{"devices": Device[], "next": "<id>"}`. `next` is set only when the page is full, and only when `limit` is 1 to 1000 or omitted.

Errors: `422` rule invalid or cannot be expanded.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/devices/query" -H 'Content-Type: application/json' \
  -d '{"rule":{"all":[{"field":"platform","op":"eq","value":"iOS"},{"field":"os_version","op":"lt","value":"latest"}]},"limit":100}'
```

#### GET /v1/devices/{id}

Returns one device, its blueprint applications and how far behind the OS is.

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `device` | Device | The record |
| `applications` | Application[] | One per blueprint item on this device (below) |
| `os_status` | object | Present when the platform and version are known: `current` (on the newest release of its major), `behind_in_major` (an update exists in its major), `newer_major_exists`, `target` (newest Release in its own major) |

Application:

| Field | Type | Meaning |
|---|---|---|
| `device` | string | Device id |
| `blueprint` | string | Blueprint id |
| `item` | string | Item id |
| `kind` | string | Item kind |
| `identifier` | string | Profile identifier, if any |
| `hash` | string | Content hash of the item version applied |
| `delivery` | string | `profile` or `declarative` |
| `server_token` | string | Declaration token the device must report active |
| `state` | string | `pending`, `applied`, `failed`, `removing`, `not_applicable` or `licensing` |
| `context` | string | Platform and OS version the decision was made for |
| `note` | string | What was left out for the platform, or why it does not apply |
| `command_uuid` | string | MDM command carrying it |
| `attempts` | int | Attempts so far |
| `error` | string | Last error |
| `updated_at` | time | Last change |

Errors: `404` unknown device.

```sh
curl -u fleetcore:$API_KEY "$API/devices/ENROLLMENT_ID"
```

#### PUT /v1/devices/{id}/tags
#### PUT /v1/devices/{id}/groups

Replace the device's tag list, or its static group list, and make the device due for reconciliation. The list is sorted before it is stored. Send an empty `values` to clear it. The group ids are not checked against existing groups, and a dynamic group id is stored without complaint (it has no effect, since dynamic membership comes from the rule).

Request body: `{"values": ["a", "b"]}` (`values`: string[]).

Response: `204` with no body. Errors: `404` unknown device.

```sh
curl -u fleetcore:$API_KEY -X PUT "$API/devices/ENROLLMENT_ID/tags" \
  -H 'Content-Type: application/json' -d '{"values":["lab","loaner"]}'
```

### Device import and expected devices

An "expected" record says what to do for a serial number when the device enrolls (name, static groups, tags). It is applied at enrollment, and immediately to a device already enrolled under that serial (name is set; groups and tags are added to what the device has).

#### POST /v1/devices/import

Records expected devices from JSON or CSV.

Query parameters (read for both content types, except where noted):

| Parameter | Meaning |
|---|---|
| `create_groups` | `true` creates a missing group as a static group named as given. JSON may also set it in the body. Otherwise a row naming an unknown group is rejected |
| `source` | Label stored on the records (for CSV). In JSON, the body's `source` is the default for rows without one |
| `columns` | CSV only. Comma-separated `field:Header` pairs mapping a field (`serial`, `name`, `user`, `groups`, `tags`) to a header, for example `serial:Serial Number,name:Computer Name` |

JSON request (`Content-Type: application/json`):

| Field | Type | Meaning |
|---|---|---|
| `devices` | Expected[] | Rows (below) |
| `create_groups` | bool | As the query parameter |
| `source` | string | Default `source` for rows |

Expected row (also returned by `GET /devices/expected`):

| Field | Type | Meaning |
|---|---|---|
| `serial` | string | Required; upper-cased and trimmed |
| `name` | string | Device name to apply |
| `user` | string | Person assigned (a note only) |
| `groups` | string[] | Static group ids |
| `tags` | string[] | Tags |
| `source` | string | Where the record came from |
| `imported_at` | time | Set by the server |

CSV request (`Content-Type: text/csv`, any value starting with `text/csv`): first row is the header. Without `columns`, headers are recognized case-insensitively ignoring punctuation:

| Field | Recognized headers |
|---|---|
| `serial` | serial, serialnumber, serialno, deviceserial, serialnumbers |
| `name` | name, devicename, computername, hostname, assetname, displayname |
| `user` | user, username, assigneduser, assignedto, email, owner, enduser, fullname |
| `groups` | groups, group, smartgroups, staticgroups, site, department, building |
| `tags` | tags, tag, labels, label, assettag |

Several groups or tags in one cell are separated by `;`, `,` or `|`. Rows may have differing column counts.

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `imported` | int | Rows recorded |
| `already_enrolled` | int | Of those, rows whose serial already had an enrolled device (applied now) |
| `groups_created` | string[] | Groups created because of `create_groups` |
| `rejected` | `{row, error}`[] | 1-based row number and reason: missing serial, group does not exist, or group is dynamic |

Errors: `422` no devices in the import, CSV without a header row, a `columns=` header that does not exist, or no serial column; `400` invalid JSON; `500`.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/devices/import?create_groups=true&source=jamf" \
  -H 'Content-Type: text/csv' --data-binary @export.csv

curl -u fleetcore:$API_KEY -X POST "$API/devices/import" -H 'Content-Type: application/json' \
  -d '{"create_groups":true,"devices":[{"serial":"C02XYZ","name":"mbp-ada","groups":["Engineering"],"tags":["loaner"]}]}'
```

#### GET /v1/devices/expected

Lists imported records, sorted by serial.

Query: `after` (serial of the last row of the previous page; note this endpoint uses `after`, not `cursor`), `limit` (1 to 1000, else 100).

Response `200`: `{"devices": Expected[], "next": "<serial>"}`. Here `next` is the last serial of the page whenever the page is not empty, so the final page returns a non-empty `next` and the following request returns an empty list.

```sh
curl -u fleetcore:$API_KEY "$API/devices/expected?limit=200"
```

#### DELETE /v1/devices/expected/{serial}

Forgets an expected record. `204` whether or not the serial existed (it does not change a device that already enrolled). `500` on store error.

```sh
curl -u fleetcore:$API_KEY -X DELETE "$API/devices/expected/C02XYZ"
```

### DEP devices

#### GET /v1/dep-devices

Devices Apple assigned to this server (ADE), known before they enroll. Sorted by serial.

Query: `cursor` (serial of the last row of the previous page), `limit` (1 to 1000, else 100).

Response `200`: `{"devices": DEPDevice[], "next": "<serial>"}`; `next` is set only when the page is full.

| DEPDevice field | Type | Meaning |
|---|---|---|
| `serial` | string | Serial number |
| `model` | string | Model |
| `os` | string | OS |
| `dep_name` | string | DEP profile name |
| `supervised` | bool | The DEP profile makes it supervised |
| `assigned_at` | time | When Apple assigned it |
| `updated_at` | time | Last update of this record |

```sh
curl -u fleetcore:$API_KEY "$API/dep-devices?limit=100"
```

### Groups

A group is static (devices are put in it with `PUT /devices/{id}/groups` or an import) or dynamic (it has a `rule`; members are the devices the rule matches).

| Group field | Type | Meaning |
|---|---|---|
| `id` | string | Taken from the path on PUT |
| `name` | string | Display name; defaults to `id` when empty |
| `description` | string | Optional |
| `rule` | Rule | Optional. Present makes the group dynamic ([Scope rules](#scope-rules)); absent makes it static |

#### GET /v1/groups

Response `200`: `{"groups": Group[]}`, sorted by name.

```sh
curl -u fleetcore:$API_KEY "$API/groups"
```

#### PUT /v1/groups/{id}

Creates or replaces a group. The body is a Group (the `id` in the body is ignored). All active devices are queued for re-evaluation. Response `200`: the stored group. Errors: `422` invalid `rule`; `400` invalid JSON. The id format is not validated here (unlike blueprint and item ids).

```sh
curl -u fleetcore:$API_KEY -X PUT "$API/groups/old-macs" -H 'Content-Type: application/json' \
  -d '{"name":"Old Macs","rule":{"all":[{"field":"platform","op":"eq","value":"macOS"},{"field":"os_version","op":"lt","value":"13.0"}]}}'
```

#### DELETE /v1/groups/{id}

Deletes a group and queues all active devices for re-evaluation. `204`; `404` unknown group. Blueprints and groups that reference it are not checked or changed; the reference then matches no device.

```sh
curl -u fleetcore:$API_KEY -X DELETE "$API/groups/old-macs"
```

### Blueprints

A blueprint is a desired state: items put on every device in `scope`. Each save creates a new revision.

#### Blueprint object

| Field | Type | Meaning |
|---|---|---|
| `id` | string | 1-64 characters, `[A-Za-z0-9][A-Za-z0-9._-]*`. Required |
| `name` | string | Defaults to `id` |
| `description` | string | Optional |
| `enabled` | bool | `false` if omitted from a request; a disabled blueprint is not applied |
| `priority` | int | When two blueprints put the same profile on a device the higher priority wins |
| `scope` | Rule | Devices it applies to; `{}` is all devices ([Scope rules](#scope-rules)) |
| `items` | Item[] | What to put on devices ([Items](#items)) |
| `rings` | Ring[] | Staged rollout; none means every device in scope at once |
| `status_items` | string[] | Extra status items devices report over the declarative status channel (names from Apple's schema, such as `passcode.is-compliant`); unknown names are a 422 |
| `keep_on_leave` | bool | Leave profiles installed when a device leaves scope or the blueprint is deleted (default: remove them) |
| `revision` | int | Set by the server: 1, then +1 per save |
| `updated_at` | time | Set by the server |
| `updated_by` | string | Basic-auth user of the last save |
| `rollout_at` | time | Set by the server: when the items last changed (unchanged if a save leaves every item identical); rings count from here |

Ring:

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Optional label |
| `percent` | int | 1 to 100; cumulative share of devices (by a stable per-device bucket) reached by this ring. Two rings may not share a percent |
| `after_seconds` | int | 0 or more; delay after `rollout_at`. Devices above the highest ring percent are never reached |

#### Items

Every item has:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Unique within the blueprint, same format as blueprint ids; empty becomes `item-<position>` |
| `kind` | string | `profile`, `command`, `declaration`, `asset`, `app`, `platform_sso`, `os_update` (anything else is a 422) |
| `name` | string | Optional label |
| `scope` | string | `system` (default) or `user`. `user` sends a declarative item to each user channel of the device (macOS users, Shared iPad) and is allowed only for kinds `declaration`, `asset` and `os_update` |
| `predicate` | string | Declarations: limits activation to devices where Apple's predicate is true on the device (for example `@status(device.model.family) == 'iPhone'`). Not allowed on `management` declarations |
| `setup` | bool | Marks an item that a device waiting in Setup Assistant must have before it is released; the server finishes setup when every setup item has applied, been found not applicable, failed for good, or the wait runs out |

Per kind:

| Kind | Field | JSON name | Type | Meaning and validation |
|---|---|---|---|---|
| `profile` | Profile | `payload` | base64 | A `.mobileconfig`. Must be a property list with `PayloadType` `Configuration` and a `PayloadIdentifier`. Omitted from `GET /blueprints` list rows |
| | Identifier | `identifier` | string | Filled from the profile's `PayloadIdentifier`; if given it must equal it |
| | Delivery | `delivery` | string | `auto` (default; legacy-profile declaration where the device takes declarative management, otherwise an MDM profile), `declarative` (insist on declarative), `profile` (always InstallProfile) |
| `command` | Request type | `request_type` | string | A command in the catalog. Unknown is a 422; commands marked destructive (can lose data or lock someone out) are refused |
| | Parameters | `params` | object | Command parameters, checked against the command's schema. Sent once per change of the item, not on every drift check |
| `declaration` | Type | `declaration_type` | string | A configuration or management declaration type in Apple's schemas, for example `com.apple.configuration.passcode.settings` |
| | Payload | `declaration` | object | Declaration payload, checked against the schema. May contain `"$asset:<item id>"` strings, which must name an `asset` item of the same blueprint |
| | No activation | `no_activation` | bool | Do not create the activation automatically |
| `asset` | Type | `declaration_type` | string | An asset type, for example `com.apple.asset.credential.userpassword` |
| | Data | `asset_data` | base64 | Optional. With it the server hosts the data and writes the asset `Reference` (URL, size, hash) itself; the type must have a `Reference` key |
| | Content type | `content_type` | string | Required with `asset_data`. Certificates: `application/pem` or `application/pkcs1`. Credential assets (SCEP, ACME, identity, user name and password): `application/json` with the keys of the credential schema |
| | Payload | `declaration` | object | With `asset_data`: only the other keys (such as `Authentication`, `Accessible`). Without: the whole asset payload, schema-checked |
| `app` | App Store number | `adam_id` | string | Digits only. Exactly one of `adam_id` or `manifest_url` is required |
| | VPP token | `vpp_token` | string | Required with `adam_id`: name of the stored Apps and Books token |
| | Manifest | `manifest_url` | string | Enterprise app manifest; must be `https://` |
| | Bundle id | `bundle_id` | string | Needed for removal. For an App Store item the server looks it up from `adam_id` when it is empty (if a resolver is configured). Required for `manifest_url` apps unless `keep_on_leave` is set |
| | Configuration | `app_config` | object | Managed app configuration |
| | Auto update | `auto_update` | string | `AlwaysOn`, `AlwaysOff` or `StoreSettings` |
| | Delivery | `delivery` | string | `auto`, `declarative` or `command` (always the InstallApplication command) |
| `platform_sso` | Preset | `preset` | string | Name of a built-in preset (extension, team, hosts); unknown is a 422 |
| | Parameters | `parameters` | map of string to string | Fill `{{name}}` placeholders in the preset; a missing one is a 422 |
| | SSO settings | `sso` | object | Extensible SSO settings in profile shape (for example `PlatformSSO`, `RegistrationToken`), laid over the preset. Must contain `ExtensionIdentifier` (from the preset or here), fit Apple's `com.apple.extensiblesso` schema, and be expressible as a declaration |
| | Delivery | `delivery` | string | `auto`, `declarative` or `profile` |
| `os_update` | Target | `target` | string | `latest`, `latest-in-major` (default when empty) or a version such as `27.0.1` |
| | Deadline days | `deadline_days` | int | 0 to 365; the deadline is that many days (default 7) after the release was published, or after the item last changed if later |
| | Deadline hour | `deadline_hour` | int or null | 0 to 23 local time (default 17) |
| | Details URL | `details_url` | string | URL shown to the user |
| | Install action | `install_action` | string | For devices that cannot take declarative enforcement but understand ScheduleOSUpdate: `Default`, `DownloadOnly`, `InstallASAP`, `NotifyOnly`, `InstallLater` or `InstallForceRestart` |

Other Item fields (`adam_id` and similar) are accepted on any kind but only the fields above are validated and used for their kind.

#### GET /v1/blueprints

Response `200`: `{"blueprints": Blueprint[]}`, ordered by priority (descending) then name. Each item's `payload` (profile bytes) is dropped to keep the list small; `GET` one blueprint for the bodies. Asset data (`asset_data`) is still included.

```sh
curl -u fleetcore:$API_KEY "$API/blueprints"
```

#### POST /v1/blueprints

Creates a blueprint. Body: a Blueprint with `id`. Response `201`: the stored Blueprint (with `revision` 1).

Errors:

| Code | Cause |
|---|---|
| 400 | Invalid JSON |
| 409 | A blueprint with that id exists (`PUT` replaces it) |
| 422 | Validation: bad id, bad scope (`scope: ...`), item errors (`item <id>: ...`), unknown status item, bad rings; or an App Store `adam_id` that cannot be resolved (`item <id>: ...`) |
| 500 | Store error |

```sh
curl -u fleetcore:$API_KEY -X POST "$API/blueprints" -H 'Content-Type: application/json' -d '{
  "id":"mac-baseline","name":"Mac baseline","enabled":true,"priority":10,
  "scope":{"field":"platform","op":"eq","value":"macOS"},
  "items":[
    {"id":"passcode","kind":"declaration","declaration_type":"com.apple.configuration.passcode.settings",
     "declaration":{"RequirePasscode":true,"MinimumLength":8}},
    {"id":"os","kind":"os_update","target":"latest-in-major","deadline_days":14}
  ],
  "rings":[{"name":"canary","percent":10,"after_seconds":0},{"name":"all","percent":100,"after_seconds":86400}]
}'
```

#### PUT /v1/blueprints/{id}

Replaces a blueprint with a new revision (the path id overrides any `id` in the body). Same body, validation and errors as POST except there is no 409, and it also creates the blueprint if the id does not exist (the response is `200` either way, not `201`). Matching devices, and devices of the previous scope, are queued for reconciliation. Because `enabled` defaults to false, send the whole blueprint (this is a replace, not a patch).

Response `200`: the stored Blueprint.

```sh
curl -u fleetcore:$API_KEY -X PUT "$API/blueprints/mac-baseline" -H 'Content-Type: application/json' -d @mac-baseline.json
```

#### GET /v1/blueprints/{id}

Response `200`: the full Blueprint including profile `payload`s. `404` unknown id.

```sh
curl -u fleetcore:$API_KEY "$API/blueprints/mac-baseline"
```

#### DELETE /v1/blueprints/{id}

Deletes the blueprint. Devices that had it are reconciled; its profiles are removed unless `keep_on_leave` was set. `204`; `404` unknown id. Revision history is not touched by this handler.

```sh
curl -u fleetcore:$API_KEY -X DELETE "$API/blueprints/mac-baseline"
```

#### GET /v1/blueprints/{id}/revisions

Up to the 50 newest revisions, newest first.

Response `200`: `{"revisions": [{"revision": 3, "updated_at": "...", "updated_by": "fleetcore", "items": 2}]}` (`items` is the item count). An unknown blueprint returns an empty list, not 404.

```sh
curl -u fleetcore:$API_KEY "$API/blueprints/mac-baseline/revisions"
```

#### POST /v1/blueprints/{id}/rollback

Saves an old revision as a new revision (the revision number goes up; history is kept).

Query: `revision` (int, required). Only the newest 1000 revisions are searched.

Response `200`: the stored Blueprint. Errors: `400` `revision=N is required`; `404` `no such revision` (also for an unknown blueprint); `500`. The old revision is stored as it was, without being validated again, so a revision that no longer passes validation (for example against newer Apple schemas) is still restored.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/blueprints/mac-baseline/rollback?revision=2"
```

#### GET /v1/blueprints/{id}/preview

Shows who a saved blueprint would reach, without changing anything.

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `devices_in_scope` | int | Count of active devices matching the scope |
| `sample` | Device[] | Up to 20 devices matching the scope (by id). Includes inactive ones |
| `rollout` | object | Counts of active devices (first 10,000 matched) by when the staged rollout reaches them: `"immediately"`, `"after <duration>"` (such as `after 24h0m0s`), or `"not reached"` (above the highest ring) |

Errors: `404` unknown blueprint; `422` scope cannot be expanded.

```sh
curl -u fleetcore:$API_KEY "$API/blueprints/mac-baseline/preview"
```

#### GET /v1/blueprints/{id}/status

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `blueprint` | string | Blueprint id |
| `revision` | int | Current revision |
| `rollout_at` | time | When the items last changed |
| `states` | object | Count of applications by state, for example `{"applied":120,"pending":4,"failed":1}`. States: `pending`, `applied`, `failed`, `removing`, `not_applicable`, `licensing`. States with no applications are absent |

Errors: `404` unknown blueprint.

```sh
curl -u fleetcore:$API_KEY "$API/blueprints/mac-baseline/status"
```

### Applicability

Overrides say on which platforms a profile payload type or preference domain applies; payloads that do not apply to a device's platform are left out of the profile sent to it. Changing an override queues every device for re-evaluation.

Override object:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Taken from the path on PUT |
| `match` | string | Payload type or preference domain; exact, or a prefix when it ends in `*` |
| `platforms` | string[] | At least one of `macOS`, `iOS`, `iPadOS`, `tvOS`, `visionOS`, `watchOS` (listing `iOS` also covers `iPadOS`) |
| `note` | string | Optional |

#### GET /v1/applicability

Response `200`: `{"overrides": Override[]}`, sorted by `match`.

```sh
curl -u fleetcore:$API_KEY "$API/applicability"
```

#### PUT /v1/applicability/{id}

Creates or replaces an override. Body: an Override (path `id` wins). Response `200`: the override. Errors: `422` missing `match` or `platforms` (`an override needs an id, a match and at least one platform`) or unknown platform; `400` invalid JSON.

```sh
curl -u fleetcore:$API_KEY -X PUT "$API/applicability/vpn" -H 'Content-Type: application/json' \
  -d '{"match":"com.apple.vpn.*","platforms":["macOS","iOS"],"note":"no VPN on tvOS"}'
```

#### DELETE /v1/applicability/{id}

`204` (also when the id does not exist); `500` on store error.

```sh
curl -u fleetcore:$API_KEY -X DELETE "$API/applicability/vpn"
```

#### POST /v1/applicability/check

Tries a profile against a platform without saving anything.

Request body:

| Field | Type | Meaning |
|---|---|---|
| `profile` | base64 | A `.mobileconfig` |
| `platform` | string | Target platform. If empty, the profile is returned unchanged |
| `os_version` | string | Target OS version |

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `not_applicable` | bool | Nothing in the profile applies; `profile` is then null |
| `left_out` | `{payload, key, reason}`[] | What was removed for the platform (`key` is omitted when a whole payload was removed) |
| `profile` | base64 | The profile as it would be sent |

Errors: `422` the profile is not a valid property list; `400` invalid JSON.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/applicability/check" -H 'Content-Type: application/json' \
  -d "{\"profile\":\"$(base64 < wifi.mobileconfig | tr -d '\n')\",\"platform\":\"tvOS\",\"os_version\":\"18.0\"}"
```

### Apple schemas

Apple's device-management definitions in use (commands, profile payloads, declarations, status items, credentials).

#### GET /v1/schemas

Response `200`: `{"ref": "<source revision>", "fetched_at": "<time>", "commands": <count>, "profile_payloads": <count>}`.

```sh
curl -u fleetcore:$API_KEY "$API/schemas"
```

#### POST /v1/schemas/refresh

Checks Apple's repository for newer definitions and, afterwards, queues every device for re-evaluation (even when nothing changed). No body.

Response `200`: `{"changed": bool, "ref": "...", "commands": n, "profile_payloads": n}`. Errors: `501` `schema refresh is not configured`; `502` the check failed.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/schemas/refresh"
```

#### GET /v1/schemas/profiles

Response `200`: `{"profiles": [{"payload_type": "com.apple.wifi.managed", "title": "Wi-Fi", "os": {...}}]}`.

`os` is a map from OS name (`iOS`, `macOS`, ...) to OS info; each has optional `introduced`, `deprecated`, `removed` (versions; `n/a` means it does not exist there), `supervised`, `requires_dep`, `user_enrollment`, `device_channel`, `user_channel`, `allowed_enrollments`, `allowed_scopes`.

```sh
curl -u fleetcore:$API_KEY "$API/schemas/profiles"
```

#### GET /v1/schemas/profiles/{type}

Returns the schema of one profile payload type (path is the `PayloadType`, for example `com.apple.wifi.managed`).

Response `200`: `{"payload_type", "title", "description", "os": {...}, "keys": Key[]}` where each Key has `key`, `type`, `required`, `default`, `allowed`, `min`, `max`, `format`, `content`, `os`, nested `keys`, `recursive` (empty ones omitted). `404` `no such payload type`.

```sh
curl -u fleetcore:$API_KEY "$API/schemas/profiles/com.apple.wifi.managed"
```

### Declarative management (DDM)

#### GET /v1/ddm/coverage

How far the fleet is on declarative management and what remains on profiles.

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `items` | object[] | One per blueprint item |
| `applications_by_delivery` | object[] | Counts of applications grouped by `kind`, `delivery` (`profile` or `declarative`), `state`, as `{kind, delivery, state, count}` |
| `profile_payloads_with_native_declarations` | int | Number of profile payload types that have a native declaration equivalent |

`items[]`:

| Field | Type | Meaning |
|---|---|---|
| `blueprint` | string | Blueprint id |
| `item` | string | Item id |
| `kind` | string | Item kind |
| `delivery` | string | The item's `delivery` setting, if any |
| `payloads` | object[] | Profile items only: one per payload type inside the profile |

`payloads[]`: `type` (payload type), `native_declarations` (equivalent declaration types), `deprecated_in` and `removed_in` (maps from OS name to version where Apple deprecated or removed the payload; omitted if none).

```sh
curl -u fleetcore:$API_KEY "$API/ddm/coverage"
```

#### POST /v1/ddm/translate

Expresses a configuration profile as native declarations where Apple has an equivalent. Nothing is saved unless `apply` is true.

Request body:

| Field | Type | Meaning |
|---|---|---|
| `profile` | base64 | The `.mobileconfig` (required) |
| `declaration` | string | Optional. Translate every payload to this one declaration type; payloads that have no such equivalent are reported as not translatable. Empty: each payload goes to all its equivalent declarations (a payload split across several declarations produces several results) |
| `blueprint` | string | Blueprint to add the resulting items to; required if `apply` is true |
| `apply` | bool | Save the items into `blueprint` as a new revision (items with an existing id are replaced) |
| `id_prefix` | string | Prefix for generated declaration item ids |

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `payloads` | object[] | One per translated payload (below) |
| `items` | Item[] or null | Items ready to add to a blueprint: `asset` items (id from the asset, such as `cert-<payload uuid>`) and `declaration` items with id `<prefix><last part of the declaration type>-<n>` where n is the payload's position among the translation results; `null` when there are none |
| `saved` | Blueprint | Present when `apply` was true: the stored blueprint |

`payloads[]` (a translation is flattened into the row):

| Field | Type | Meaning |
|---|---|---|
| `payload_type` | string | The profile payload's `PayloadType` |
| `declaration` | string | Declaration type it was translated to |
| `payload` | object | The declaration payload |
| `approximate` | map | Profile key to why it was translated to the closest setting |
| `untranslated` | string[] | Profile keys not carried over (need a person's decision) |
| `reasons` | map | Untranslated key to why, where known |
| `assets` | Asset[] | Data the payload refers to by `$asset:<id>`: `id`, `declaration_type`, `content_type`, `data` (base64) |
| `note` | string | Present, with no translation fields, when the payload type has no native declaration: keep it as a profile |

Errors: `400` invalid JSON, or `apply needs the blueprint to add the items to`; `422` the profile is not a valid property list, or two payloads produce the same asset id with different content; `404` (apply) `no such blueprint`; on apply, the save runs the usual blueprint validation, so `422`/`500` as for `PUT /blueprints/{id}`.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/ddm/translate" -H 'Content-Type: application/json' \
  -d "{\"profile\":\"$(base64 < passcode.mobileconfig | tr -d '\n')\",\"blueprint\":\"mac-baseline\",\"apply\":false,\"id_prefix\":\"t-\"}"
```

#### GET /v1/ddm/translate/coverage

How much of each profile payload type the translator covers, judged from the pinned schemas and the alias table; useful after a schema update.

Response `200`: `{"schema": "<ref>", "payloads": CoverageRow[]}`:

| CoverageRow field | Type | Meaning |
|---|---|---|
| `payload_type` | string | Profile payload type |
| `declaration` | string | Declaration it is measured against (one row per equivalent declaration) |
| `profile_keys` | int | Profile keys judged |
| `translated` | int | Keys that translate to this declaration |
| `explained` | int | Keys with no counterpart and a documented reason |
| `unmapped` | string[] | Keys nobody has looked at |
| `declaration_only` | string[] | Declaration keys with no profile counterpart |

```sh
curl -u fleetcore:$API_KEY "$API/ddm/translate/coverage"
```

#### GET /v1/ddm/support

From which OS version declarative management and its software-update features are available.

Query: `platform` (optional). Without it, a per-platform summary; with it, every declaration type available on that platform.

Response `200` without `platform`: `{"schema": "<ref>", "platforms": PlatformSupport[]}` for iOS, macOS, tvOS, visionOS and watchOS (iPadOS shares iOS):

| Field | Type | Meaning |
|---|---|---|
| `platform` | string | Platform |
| `base` | string | First OS version that takes declarative management |
| `legacy_profiles` | string | First version that can take a configuration profile as a declaration |
| `software_update` | object | `enforcement`, `enforcement_enrollments`, `settings`, `status_items` (versions, `n/a` where none), `mdm_commands_removed_in` |
| `configurations` | int | Number of configuration types |
| `base_enrollments` | string[] | Enrollments a baseline declaration allows |

Response `200` with `platform`: `{"platform": "macOS", "schema": "<ref>", "declarations": [{"type","kind","introduced","enrollments","apply"}]}` sorted by type (the platform name is not validated; an unknown one yields an empty or null list).

```sh
curl -u fleetcore:$API_KEY "$API/ddm/support"
curl -u fleetcore:$API_KEY "$API/ddm/support?platform=macOS"
```

#### GET /v1/ddm/devices/{id}

The declarations the server holds for a device, its sync state and what it last reported.

Response `200`:

| Field | Type | Meaning |
|---|---|---|
| `declarations` | object[] | `identifier`, `kind`, `type`, `server_token`, `source` (`<blueprint>/<item>` or `system`), `payload` |
| `sync` | object | Sync state. This struct has no JSON tags, so the keys are the Go names: `Token`, `UpdatedAt`, `NotifiedToken`, `NotifiedAt`, `SyncedToken`, `SyncedAt` |
| `status` | map | Declaration identifier to `{identifier, server_token, active, valid, reasons}` as last reported; null if nothing reported |
| `status_items` | map | Status item values the device reported; null if none |
| `status_at` | time | When the device last reported (zero time if never) |

Errors: `501` `declarative management is not enabled`; `500`. An unknown device returns `200` with empty declarations (it is not a 404).

```sh
curl -u fleetcore:$API_KEY "$API/ddm/devices/ENROLLMENT_ID"
```

### OS releases

Apple OS releases, used for `latest` and `latest-in-major` and for `os_status`.

Release object: `platform`, `version`, `build`, `major`, `published_at`, `expires_at` (when Apple stops offering it; GDMF source only), `source` (`gdmf` or `rss`).

#### GET /v1/os-releases

Query: `platform` (optional exact match, such as `macOS`).

Response `200`: `{"releases": Release[], "updated_at": "<time>"}`.

```sh
curl -u fleetcore:$API_KEY "$API/os-releases?platform=iOS"
```

#### GET /v1/os-releases/latest

Response `200`: an object keyed by platform (`macOS`, `iOS`, `iPadOS`, `tvOS`, `watchOS`, `visionOS`; platforms with no release are absent), each `{"latest": Release, "by_major": {"<major>": "<newest version in that major>"}}`.

```sh
curl -u fleetcore:$API_KEY "$API/os-releases/latest"
```

#### POST /v1/os-releases/refresh

Fetches the releases feed now. No body. Response `200`: `{"new_releases": <count>}`. Errors: `501` `the releases feed is not configured`; `502` the fetch failed.

```sh
curl -u fleetcore:$API_KEY -X POST "$API/os-releases/refresh"
```

## Commands, listings, workflows, apps and NanoMDM's API

All endpoints below are under `/v1` and sit behind the management-API guard (`adminAuth` in `fleetcore/server/server.go`): a client certificate chaining to the admin CA (when `AdminCA` is set) and/or HTTP basic auth with user `fleetcore` and the API key (the user name is not checked, only the password; `-u fleetcore:$API_KEY` is the convention). Both are required when both are configured. Failures are `401` with a plain-text body. An optional `X-Actor` header is appended to the audited identity (`who`) when a certificate or key is in use; every call is logged, and the workflows record `who` in the audit trail. Examples use `$HOST` for the server base URL.

Conventions used by the JSON handlers in this section: bodies are `Content-Type: application/json`; errors are `{"error": "..."}` unless noted. Paging (`limit`, `cursor`, `next`) is described once, under Listings.

### JSON command API

Source: `fleetcore/commands/http.go`, `build.go`, `schema.go`. Mounted at `/v1/commands` and `/v1/commands/`. Apple's MDM commands are validated against Apple's schema (a catalog that follows Apple's releases), converted from JSON to the plist a device receives, and queued with a push.

JSON value mapping used by `params`: strings, booleans, integers (whole JSON numbers), reals, `data` as base64 strings, `date` as RFC 3339 strings, dictionaries as objects, arrays as arrays. Where the schema does not describe a dictionary, it is passed through as given (whole numbers become integers).

#### `GET /v1/commands/types`

Lists every command in the catalog (sorted by `RequestType`). No query parameters. Any method reaches this handler (it does not check the method).

Response `200`:

| Field | Type | Notes |
|---|---|---|
| `ref` | string | The Apple release the schema set comes from |
| `commands` | array | One row per command, below |

Row fields:

| Field | Type | Notes |
|---|---|---|
| `request_type` | string | e.g. `DeviceLock` |
| `title` | string | |
| `description` | string | omitted when empty |
| `destructive` | bool | omitted when false; `confirm: true` is required to send |
| `os` | object | omitted when empty; keyed by OS name (`macOS`, `iOS`, ...) with per-OS support info (`OSInfo` from the schema: introduced/removed versions, supervised, User Enrollment rules) |

```sh
curl -u fleetcore:$API_KEY $HOST/v1/commands/types
```

#### `GET /v1/commands/types/{RequestType}`

Returns one command's schema (the full `Command` object: the fields above plus its `keys` tree describing the allowed `params`).

| Status | When |
|---|---|
| `200` | The `Command` object |
| `404` | `{"error": "no such command", "problems": null}` |

```sh
curl -u fleetcore:$API_KEY $HOST/v1/commands/types/DeviceLock
```

#### `POST /v1/commands`

Validates, builds and queues a command for one or more enrollments, then sends an APNs push (unless `no_push`). Body limit 4 MiB. `POST /v1/commands/` is equivalent.

Request body:

| Field (`json`) | Type | Required | Notes |
|---|---|---|---|
| `request_type` | string | yes | An MDM command, e.g. `DeviceLock`. Unknown: `422` |
| `params` | object | per command | The command's keys, validated against the schema |
| `devices` | string[] | yes | Enrollment IDs (UDIDs). Empty: `422 "devices is empty"` |
| `platform` | string | no | `macOS`, `iOS`, `tvOS`, `visionOS`, `watchOS` (`iPadOS` is treated as `iOS`). Rejects commands and keys that do not exist there |
| `confirm` | bool | for destructive commands | Must be `true` for commands in the destructive set |
| `no_push` | bool | no | Queue without waking the devices |
| `command_uuid` | string | no | Your own CommandUUID; a random upper-case UUID is generated otherwise |

Notes on validation:

- The API does not know the target devices' OS version or enrollment type; only `platform` (if given) is used. The per-device checks (OS version, User Enrollment, supervision) are applied by the device workflows, not here.
- The destructive set (`fleetcore/schemas/schemas.go`): `EraseDevice`, `DeviceLock`, `ClearPasscode`, `DeleteUser`, `ClearRestrictionsPassword`, `EnableLostMode`, `RestartDevice`, `ShutDownDevice`, `SetFirmwarePassword`, `SetRecoveryLock`, `RemoveProfile`, `RemoveApplication`, `LogOutUser`, `RotateFileVaultKey`. Without `"confirm": true` the call fails with `422` and message `<Type> can lose data or lock someone out: send "confirm": true to proceed`. The check runs after the type and `devices` checks and before parameter validation.
- Parameter problems are all reported together as `problems`, each with a `path` into `params` (`Queries[1]`, `ReturnToService.Enabled`) and a `message`. Messages include: `is required`, `is not a key of this command`, `must be a string`, `must be true or false`, `must be an integer`, `must be a number`, `must be a base64 string`, `is not valid base64`, `must be an RFC 3339 date string`, `must be an object`, `must be an array`, `does not match the format <regex>`, `must be at least N`, `must be at most N`, `must be one of a, b, c`, `does not exist on <platform>`. Platform-level problems have an empty `path`: `<Type> does not exist on <platform>`.

Response `200` (also see the status note below):

| Field | Type | Notes |
|---|---|---|
| `command_uuid` | string | Use it with `GET /v1/commands/{uuid}` |
| `request_type` | string | |
| `result` | object | NanoMDM's `APIResult`, see "NanoMDM API result" below |

Status codes:

| Status | When |
|---|---|
| `200` | Accepted. The per-device outcome is in `result.status`; see the inconsistency note |
| `400` | Body is not valid JSON (`"the body is not valid JSON: ..."`) |
| `422` | Unknown `request_type`, empty `devices`, destructive without `confirm`, or invalid command (`"error": "the command is not valid"` with `problems`) |
| `500` | The built command could not be decoded or enqueued as a whole |

Error bodies have the shape `{"error": "...", "problems": [...]}` (`problems` is `null` when empty).

Inconsistency: the handler returns `207` when the enqueue helper returns an error alongside a result, but that helper never does, and the per-enrollment status code it computes (`200`/`207`/`500`) is discarded. In practice a partial or total failure to enqueue or push still returns `200`; check `result.status.<id>.command_error` / `push_error` and `result.command_error` / `push_error`.

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/commands \
  -H 'Content-Type: application/json' \
  -d '{"request_type":"DeviceLock","params":{"Message":"Call IT"},"devices":["00008103-001234567890001E"],"platform":"macOS","confirm":true}'
```

```json
{"command_uuid":"5C0D...","request_type":"DeviceLock","result":{"status":{"00008103-001234567890001E":{"push_result":"3C5B..."}},"command_uuid":"5C0D...","request_type":"DeviceLock"}}
```

Validation failure:

```json
{"error":"the command is not valid","problems":[{"path":"Message","message":"must be a string"}]}
```

#### `GET /v1/commands`

The command history, newest first (by creation time, then ID), in pages.

| Query parameter | Notes |
|---|---|
| `type` | Only commands with this `RequestType` |
| `include=contents` | Any other value (or none) omits contents. With `contents` each row carries the command as JSON (opened if sealed) |
| `cursor` | Opaque cursor from the previous page's `next` |
| `limit` | Default 100, maximum 1000 (larger is clamped; non-numeric/<=0 gives the default) |

Response `200`: `{"commands": [...], "next": "<cursor or empty>"}`. Row fields:

| Field | Type | Notes |
|---|---|---|
| `command_uuid` | string | |
| `request_type` | string | |
| `created_at` | RFC 3339 | |
| `command` | object | only with `include=contents` and when the stored command could be read |

| Status | When |
|---|---|
| `400` | Bad cursor or storage error (all errors are reported as `400`) |
| `501` | The storage cannot list commands (not the MongoDB storage) |

Note: a trailing-slash-less path (`/v1/commands`) and `/v1/commands/` both list.

```sh
curl -u fleetcore:$API_KEY "$HOST/v1/commands?type=DeviceLock&include=contents&limit=20"
```

#### `GET /v1/commands/{uuid}`

Reads back what each device did with a command.

Response `200`: `{"command_uuid": "...", "devices": [ ... ]}` with one row per enrollment the command was queued for (up to 10000):

| Field | Type | Notes |
|---|---|---|
| `id` | string | Enrollment ID |
| `status` | string | `Queued` until the device answers, then the MDM status (`Acknowledged`, `Error`, `CommandFormatError`, `NotNow`) |
| `queued_at` | RFC 3339 | |
| `result_at` | RFC 3339 | omitted until answered |
| `result` | object | the device's response as JSON (data as base64, dates as RFC 3339); omitted until answered |

| Status | When |
|---|---|
| `404` | `{"error":"no such command","problems":null}`: unknown UUID, or the command was removed after completion (storage option `WithDeleteCommands`) |
| `500` | Storage error |
| `501` | The storage cannot report results |
| `405` | A method other than GET/POST on a path under the prefix |

```sh
curl -u fleetcore:$API_KEY $HOST/v1/commands/5C0D0F7E-1111-4222-8333-944455556666
```

### Listings

Source: `fleetcore/server/listing.go`, `storage/mongodb/query.go`. Available only when the storage is MongoDB. Mounted at `/v1/enrollments`, `/v1/enrollments/` and `/v1/queue`. Only `GET` is routed (other methods are `405` from the Go 1.22 mux).

Paging for all lists (including `GET /v1/commands`): `limit` defaults to 100 and is clamped to 1000. The response has `next`, an opaque URL-safe base64 keyset cursor; pass it back as `cursor` to continue. `next` is the empty string exactly when there are no more rows (the server reads one row beyond the page to know). Cursors stay valid while data is added and never skip or repeat a row. A malformed cursor gives `400` (`bad cursor`).

#### `GET /v1/enrollments`

Lists enrolled channels ordered by `id`.

| Query parameter | Notes |
|---|---|
| `device` | Exact `device_id` |
| `type` | Enrollment type: `Device`, `User`, `User Enrollment (Device)`, `User Enrollment`, `Shared iPad` |
| `enabled` | `true` or `1` selects enabled; any other non-empty value selects disabled; empty means both |
| `cursor`, `limit` | Paging |

Response `200`: `{"enrollments": [...], "next": "..."}`. Row fields:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Enrollment ID |
| `device_id` | string | |
| `user_id` | string | omitted when empty |
| `type` | string | |
| `topic` | string | APNs topic |
| `enabled` | bool | |
| `last_seen_at` | RFC 3339 | |
| `enrolled_at` | RFC 3339 | |

Errors: `400` with `{"error": ...}` (bad cursor, storage error).

```sh
curl -u fleetcore:$API_KEY "$HOST/v1/enrollments?type=Device&enabled=true&limit=50"
```

#### `GET /v1/enrollments/{id}`

One enrollment (the object above, unwrapped). `404 {"error":"not found"}` if none, `500` on storage error.

```sh
curl -u fleetcore:$API_KEY $HOST/v1/enrollments/00008103-001234567890001E
```

#### `GET /v1/enrollments/{id}/queue` and `GET /v1/queue`

The command queue (one entry per command per enrollment) in the order queued. The first is limited to one enrollment; `/v1/queue` spans enrollments and takes the enrollment as `id=`.

| Query parameter | Notes |
|---|---|
| `id` | `/v1/queue` only: enrollment ID filter (empty: all) |
| `status` | Case-insensitive: `pending` (or `queued`: no answer yet), `acknowledged`, `error` (matches `Error` and `CommandFormatError`), `notnow`. Empty: all. Any other value matches nothing (empty list, not an error) |
| `type` | `RequestType` filter (resolved by looking up up to 50,000 commands of that type) |
| `command` | Command UUID filter |
| `cursor`, `limit` | Paging |

Response `200`: `{"queue": [...], "next": "..."}`. Row fields:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Enrollment ID |
| `command_uuid` | string | |
| `request_type` | string | omitted if the command is gone |
| `status` | string | `Queued` or the device's last status |
| `active` | bool | |
| `priority` | int | |
| `queued_at` | RFC 3339 | |
| `result_at` | RFC 3339 | omitted until answered |
| `not_now_tally` | int | omitted when 0 |

Errors: `400 {"error": ...}`.

Inconsistency: `/v1/enrollments/{id}/queue` ignores an `id` query parameter (the path wins) while `/v1/queue` honors it.

```sh
curl -u fleetcore:$API_KEY "$HOST/v1/enrollments/00008103-001234567890001E/queue?status=pending"
curl -u fleetcore:$API_KEY "$HOST/v1/queue?type=DeviceLock&status=error&limit=100"
```

### Device workflows

Source: `fleetcore/workflows/http.go`, `workflows.go`, `fleetcore/vault/vault.go`. These routes are served under `/v1/devices/{id}/...` by the workflow API, which falls back to the blueprint/device API for every other `/v1/devices` path. `{id}` is the device ID (the same ID blueprints use, normally the enrollment ID/UDID).

How they work: each command workflow looks up the device record, builds the command with `commands.Build` using the device's `Platform`, `OSVersion` and whether it is a User Enrollment (enroll type contains `User Enrollment`), checks the schema's supervised requirement, queues the command to that one device (the device is not pushed by the workflow itself beyond what the enqueuer does), records which workflow and who started it (`wf_commands`, kept 30 days), and returns `202 {"command_uuid": "..."}`. When the device acknowledges, the result is filed: apps and Lost Mode state on the device record, secrets in the vault. Read the raw command result with `GET /v1/commands/{uuid}`.

Common responses of the command workflows:

| Status | Body | When |
|---|---|---|
| `202` | `{"command_uuid": "..."}` | Queued |
| `400` | `{"error": "the body is not valid JSON"}` | Unparseable body (workflows with a body) |
| `404` | `{"error": "not found"}` | Unknown device |
| `422` | `{"error": "..."}` | The device cannot do this (`ErrUnavailable`): the command is not in the schema, does not exist on its platform or OS version, is forbidden on User Enrollment (BYOD), uses a key forbidden there, needs a supervised device (`<Type> needs a supervised <Platform> device`; a device with unknown supervision is treated as not supervised), or a Lost Mode precondition. The message is the first schema problem, e.g. `ActivationLockBypassCode does not exist on macOS` |
| `500` | `{"error": "..."}` | Anything else, including the plain validation errors noted per endpoint |

Which devices refuse what is decided by Apple's schema for the device's platform, OS version and enrollment, not by hard-coded rules in the workflows (for example, the code does not itself check whether a Mac is Apple silicon or Intel; a wrong-architecture command is simply rejected by the device).

#### `GET /v1/devices/{id}/secrets`

Lists stored secrets (metadata only, never values), ordered by `kind` then newest version first, including all versions.

Response `200`:

| Field | Type | Notes |
|---|---|---|
| `secrets` | array or `null` | `null` when nothing is stored |
| `secrets[].device` | string | |
| `secrets[].kind` | string | `filevault-recovery-key`, `recovery-lock`, `firmware-password`, `activation-lock-bypass` |
| `secrets[].version` | int | |
| `secrets[].current` | bool | |
| `secrets[].created_at` | RFC 3339 | |
| `secrets[].created_by` | string | who started the workflow |
| `bootstrap_token` | object | `{"escrowed": true}`, present only when the MDM storage holds a bootstrap token for the device |

Errors: `500` on storage error. Listing is not audited.

```sh
curl -u fleetcore:$API_KEY $HOST/v1/devices/00008103-001234567890001E/secrets
```

#### `POST /v1/devices/{id}/secrets/{kind}/reveal`

Returns a secret value. The access is written to the audit trail first ("no record, no secret"); the value is stored sealed with the tenant key.

Request body:

| Field (`json`) | Type | Required | Notes |
|---|---|---|---|
| `reason` | string | yes | Non-blank; recorded in the audit |
| `version` | int | no | `0`/omitted: the current version |

`kind` is one of the kinds above, or `bootstrap-token` (read from the MDM storage; audited the same way).

Response `200`: `{"kind": "...", "version": 3, "created_at": "...", "value": "..."}`. For `bootstrap-token` only `{"kind","value"}` are returned (no `version`/`created_at`).

| Status | When |
|---|---|
| `400` | Body not JSON, or empty `reason` (`say why the secret is needed: it is recorded`) |
| `404` | No such secret/version (nothing is audited in that case for vault kinds; for `bootstrap-token` the reveal is audited before the lookup, so a missing token is still recorded) |
| `501` | `bootstrap-token` and the storage cannot read bootstrap tokens |
| `500` | Other errors |

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/secrets/filevault-recovery-key/reveal \
  -H 'Content-Type: application/json' -d '{"reason":"user locked out, ticket 4812"}'
```

#### `GET /v1/devices/{id}/secrets/audit`

Who stored or revealed what, newest first.

| Query parameter | Notes |
|---|---|
| `limit` | Default 100; values <= 0 or > 1000 also give 100 |

Response `200`: `{"audit": [ {"device","kind","action","who","reason","at"} ]}`. `action` is `stored` or `revealed`; `who` is the certificate subject or `api key` (plus ` (X-Actor)`); `reason` is omitted when empty. `audit` is `null` when empty. No paging cursor. Reading the audit is not itself audited.

```sh
curl -u fleetcore:$API_KEY "$HOST/v1/devices/00008103-001234567890001E/secrets/audit?limit=20"
```

#### `POST /v1/devices/{id}/apps/refresh`

Queues `InstalledApplicationList` to refresh the stored list. On a User Enrollment `ManagedAppsOnly: true` is sent (all the organization may see). No body. `202 {"command_uuid"}`. When acknowledged, the device record's `apps` and `apps_at` are updated (`identifier`, `name`, `version`, `short_version`, `managed`).

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/apps/refresh
```

#### `GET /v1/devices/{id}/apps`

What is installed as the device last reported. Response `200`: `{"apps": [...] , "reported_at": "..."}`. Each app: `identifier`, `name` (omitted if empty), `version`, `short_version`, `managed` (omitted when false). `apps` is `null` and `reported_at` is `0001-01-01T00:00:00Z` before the first report. `404` for an unknown device.

```sh
curl -u fleetcore:$API_KEY $HOST/v1/devices/00008103-001234567890001E/apps
```

#### `POST /v1/devices/{id}/lost-mode`

Queues `EnableLostMode` (supervised iPhone/iPad by Apple's schema; unsupervised or other platforms are `422`). The device's `lost_mode` is set to enabled and confirmed only when the device acknowledges.

Request body:

| Field (`json`) | Type | Notes |
|---|---|---|
| `message` | string | Shown to the finder |
| `phone` | string | Sent as `PhoneNumber` |
| `footnote` | string | |

At least one of `message` or `phone` is required; otherwise the error is `500 {"error": "Lost Mode needs a message or a phone number to show"}` (not a 4xx). Response `202 {"command_uuid"}`.

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/lost-mode \
  -H 'Content-Type: application/json' -d '{"message":"Lost. Please call","phone":"+15555550100"}'
```

#### `DELETE /v1/devices/{id}/lost-mode`

Queues `DisableLostMode`. No body. `202 {"command_uuid"}`; on acknowledgement `lost_mode.enabled` becomes false.

#### `GET /v1/devices/{id}/lost-mode`

Response `200`: `{"lost_mode": {...}, "location": {...}}`, each `null` until set. `lost_mode`: `enabled`, `message`, `phone`, `footnote` (omitted if empty), `confirmed` (the device acknowledged), `since`. `location`: `latitude`, `longitude`, `altitude`, `horizontal_accuracy` (the last two omitted when 0), `at`. `404` for an unknown device.

#### `POST /v1/devices/{id}/locate`

Queues `DeviceLocation`; the answer is stored as the device's `location` (read it from `GET .../lost-mode`). Refused with `422 "a device can be located only while it is in Lost Mode"` unless the record says Lost Mode is enabled. No body. `202`.

#### `POST /v1/devices/{id}/play-sound`

Queues `PlayLostModeSound`. Refused with `422 "the sound plays only while the device is in Lost Mode"` unless Lost Mode is enabled. No body. `202`.

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/locate
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/play-sound
```

#### `POST /v1/devices/{id}/activation-lock/bypass-code`

Queues `ActivationLockBypassCode` (supervised device). No body. `202`. The code in the device's answer is stored in the vault (kind `activation-lock-bypass`, `created_by` the requester); read it with the reveal endpoint. Nothing is stored if the device sends no code.

#### `DELETE /v1/devices/{id}/activation-lock/bypass-code`

Queues `ClearActivationLockBypassCode`. No body. `202`. The stored vault copy is not removed.

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/activation-lock/bypass-code
```

#### `POST /v1/devices/{id}/filevault/rotate`

Rotates the Mac's personal FileVault recovery key (`RotateFileVaultKey`, `KeyType: personal`). The server generates a one-time RSA-2048 key and a self-signed certificate valid 48 hours, sends the certificate as `ReplyEncryptionCertificate`, and keeps the private key sealed with the tracked command. When the Mac acknowledges, the new key is decrypted and stored in the vault (`filevault-recovery-key`, new version; the previous version stays).

Request body (optional):

| Field (`json`) | Type | Notes |
|---|---|---|
| `password` | string | A password that unlocks FileVault. Empty: the currently stored recovery key is used (the previous recovery key is accepted as the password). With none stored: `500 "no recovery key is stored for this Mac: give a password that can unlock FileVault"` |

`202 {"command_uuid"}`. The password is sent to the device in the command and is not stored by the workflow. `RotateFileVaultKey` is in the destructive set for the generic API, but this endpoint needs no `confirm`.

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/filevault/rotate \
  -H 'Content-Type: application/json' -d '{}'
```

#### `POST /v1/devices/{id}/recovery-lock`

Sets, changes or clears the recovery lock (`SetRecoveryLock`, Apple silicon Macs). The stored current password, if any, is sent as `CurrentPassword`.

#### `POST /v1/devices/{id}/firmware-password`

Same, with `SetFirmwarePassword` (Intel Macs) and the vault kind `firmware-password`.

Request body for both (optional):

| Field (`json`) | Type | Notes |
|---|---|---|
| `password` | string | The new password. Empty: the server generates a 16-character one |
| `clear` | bool | `true` sends an empty `NewPassword` (clears it); `password` is ignored |

`202 {"command_uuid"}`. The new password is kept sealed with the tracked command and written to the vault (kinds `recovery-lock`, `firmware-password`) only when the device acknowledges; for a clear, an empty value is stored as a new version. The password never appears in the response; use reveal.

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/devices/00008103-001234567890001E/recovery-lock \
  -H 'Content-Type: application/json' -d '{"clear":false}'
```

Sealing and auditing summary:

| Item | Sealed at rest | Audited |
|---|---|---|
| Vault secrets (FileVault key, recovery lock, firmware password, bypass code) | yes (`vault.<kind>` purpose) | `stored` on write (who started the workflow), `revealed` on reveal |
| FileVault one-time private key, pending lock passwords (`wf_commands.extra`) | yes (`workflow.extra`) | no |
| Bootstrap token | held by MDM storage | `revealed` on reveal |
| Lost Mode, location, apps | no (device record) | no |

### Apps and Books (VPP)

Source: `fleetcore/vpp/http.go`, `store.go`, `client.go`. Mounted at `/v1/vpp/`. `{name}` is the name you gave the stored service token. Tokens are kept sealed and never returned.

#### `GET /v1/vpp/tokens`

Response `200`: `{"tokens": [...]}` with `name`, `org_name`, `location_name`, `expires`, `added_at`. `500` on storage error.

```sh
curl -u fleetcore:$API_KEY $HOST/v1/vpp/tokens
```

#### `PUT /v1/vpp/tokens/{name}`

Stores (or replaces, upsert) a token after Apple accepts it (a client-config call to Apple's Apps and Books service).

Request body (limit 1 MiB):

| Field (`json`) | Type | Notes |
|---|---|---|
| `token` | string | The service token file contents from Apple Business Manager (base64) |

Response `200`: the token info (`name`, `org_name`, `location_name`, `expires`, `added_at`).

| Status | When |
|---|---|
| `400` | Body is not valid JSON |
| `422` | Token not base64, expired, or rejected by Apple (`Apple did not accept the token: ...`) |

```sh
curl -u fleetcore:$API_KEY -X PUT $HOST/v1/vpp/tokens/main \
  -H 'Content-Type: application/json' -d "{\"token\":\"$(cat vpp.vpptoken)\"}"
```

#### `DELETE /v1/vpp/tokens/{name}`

Deletes the token. `204` with no body (also when it did not exist); `500` on storage error.

#### `GET /v1/vpp/{name}/assets`

Owned apps and license counts, from Apple.

| Query parameter | Notes |
|---|---|
| `adam_id` | Limit to one app (App Store ID) |

Response `200`: `{"assets": [...]}`; each asset: `adamId`, `pricingParam`, `productType`, `deviceAssignable`, `revocable`, `supportedPlatforms`, `totalCount`, `assignedCount`, `retiredCount`, `availableCount` (camelCase, as in Apple's API).

#### `GET /v1/vpp/{name}/assignments`

| Query parameter | Notes |
|---|---|
| `serial` | Limit to one device serial number |
| `adam_id` | Limit to one app |

Response `200`: `{"assignments": [{"adamId","pricingParam","serialNumber"}]}`.

Errors for both: `404` with `{"error": "no Apps and Books token named \"x\""}` (also for other client-construction errors), `502` when Apple's service fails.

```sh
curl -u fleetcore:$API_KEY "$HOST/v1/vpp/main/assets?adam_id=497799835"
curl -u fleetcore:$API_KEY "$HOST/v1/vpp/main/assignments?serial=C02XXXXXXXXX"
```

#### `POST /v1/vpp/{name}/assign` and `POST /v1/vpp/{name}/unassign`

Assigns licenses of the apps to device serial numbers, or takes them back. Apple accepts the request and performs it afterwards.

Request body (limit 1 MiB):

| Field (`json`) | Type | Required |
|---|---|---|
| `adam_ids` | string[] | yes, non-empty |
| `serials` | string[] | yes, non-empty |

Response `202`: `{"eventId": "...", "eventStatus": "PROCESSING"}` (`eventStatus` is `PROCESSING`, `COMPLETE` or `FAILED`; there is no endpoint here to poll it).

| Status | When |
|---|---|
| `400` | Invalid JSON or either list empty (`adam_ids and serials are required`) |
| `404` | Unknown token name |
| `502` | Apple's service failed |

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/vpp/main/assign \
  -H 'Content-Type: application/json' -d '{"adam_ids":["497799835"],"serials":["C02XXXXXXXXX"]}'
```

### Migration

Source: `fleetcore/server/server.go`, `http/mdm/mdm.go`, `service/request.go`.

#### `/v1/migration`

Mounted only when the server runs with `-migration` (`Migration: true`). It takes check-in messages from enrollments of another NanoMDM-family server (see `cmd/nano2nano`) and creates the enrollments here without a certificate check, so devices keep their enrollment when the MDM address moves. It uses the MDM service from before the certificate-auth wrapper. The method is not checked (use `PUT`). Management-API auth applies.

Request body: one raw check-in plist (Content-Type is not checked; it is the same `application/x-apple-aspen-mdm-checkin` plist body a device sends). Documented message types are `Authenticate`, `TokenUpdate` and `SetBootstrapToken`. The enrollment identity is taken from the request the same way as for the device endpoints (certificate/enrollment ID headers as configured), so supply the enrollment ID the same way nano2nano does.

| Status | When |
|---|---|
| `200` | Accepted; the body is empty for these message types |
| `400` | The plist is not a valid check-in |
| other | Status carried by the service error, `500` otherwise (plain text) |

Inconsistency: the handler is the generic check-in handler, so it also processes `CheckOut`, `UserAuthenticate`, `GetBootstrapToken`, `DeclarativeManagement` and `GetToken` messages, not only the three documented. Also, on an error the code writes the error status and then still writes the (empty) response bytes.

```sh
curl -u fleetcore:$API_KEY -X PUT --data-binary @tokenupdate.plist $HOST/v1/migration
```

### NanoMDM's own API

Source: `http/api/v1.go`, `api.go`, `pushcert.go`, `escrowkeyunlock.go`, `api/`. Registered by `httpapi.HandleAPIv1("/v1", ...)` behind the same management auth. Multiple enrollment IDs are given as a comma-separated list in the URL path. The path is used as is (no URL decoding beyond Go's, no whitespace trimming), so IDs containing commas or slashes cannot be addressed.

Neither `/v1/push/` nor `/v1/enqueue/` checks the HTTP method.

#### NanoMDM API result

Returned by push and enqueue (and nested as `result` in `POST /v1/commands`). Responses are pretty-printed with tab indent.

| Field | Type | Notes |
|---|---|---|
| `status` | object | Keyed by enrollment ID, each with the fields below; omitted if empty |
| `no_push` | bool | Pushes were not sent for this call |
| `push_error` | string | Call-level push error |
| `command_error` | string | Call-level enqueue error |
| `command_uuid` | string | The enqueued command |
| `request_type` | string | The enqueued command's type |

`status.<id>` fields: `push_result` (the APNs `apns-id`), `push_error`, `command_error` (strings, omitted when empty).

HTTP status of push/enqueue: `200` when no errors; `207` when some enrollments failed; `500` when a call-level error occurred or every enrollment failed (also when the path is empty).

#### `GET|PUT /v1/pushcert`

`GET` returns the stored APNs push certificate's expiry. Query parameter `topic` (required), e.g. `com.apple.mgmt.External.xxxxx`.

Response `200`: `{"topic": "...", "not_after": "RFC 3339"}`.

| Status | When |
|---|---|
| `400` | `{"error": "missing required query parameter: topic"}` |
| `500` | Certificate not found or cannot be parsed (`{"error": ...}`) |
| `405` | Any method other than GET/PUT (plain text) |

`PUT` uploads the push certificate and its unencrypted private key. Body is raw PEM (certificate and key, in either order; blocks mashed together without a newline are tolerated). Content type is not checked. Response `200` with the same `{topic, not_after}` shape; the topic comes from the certificate's UID.

| Status | When |
|---|---|
| `400` | Unusable PEM: unrecognized PEM type, encrypted key, cert/key pair mismatch, cert unparseable, no topic |
| `500` | Body read or storage failure |

```sh
curl -u fleetcore:$API_KEY "$HOST/v1/pushcert?topic=com.apple.mgmt.External.0000"
cat push.pem push.key | curl -u fleetcore:$API_KEY -T - $HOST/v1/pushcert
```

#### `/v1/push/{id[,id...]}`

Sends an APNs push ("wake up and check in") to one or more enrollments. No body, no query parameters. Response: the NanoMDM API result above (`push_result` per ID).

```sh
curl -u fleetcore:$API_KEY $HOST/v1/push/00008103-001234567890001E,00008103-001234567890001F
```

#### `/v1/enqueue/{id[,id...]}`

Enqueues a raw MDM command plist (the body) to one or more enrollments, then pushes. This is the low-level equivalent of `POST /v1/commands` with no validation beyond the plist parsing as an MDM command.

| Query parameter | Notes |
|---|---|
| `nopush` | Any non-empty value (including `0`) skips the push |

Request body: the full command plist (`CommandUUID` and `Command` with `RequestType`). Response: the NanoMDM API result, with `command_uuid` and `request_type` filled in.

| Status | When |
|---|---|
| `200` / `207` / `500` | As above |
| `500` | The plist cannot be decoded as a command (`command_error`), or the body cannot be read |

Inconsistency: when reading the body fails, the handler assigns the error to a shadowed variable, so the response is the generic nil-result error (`500` with `command_error: "nil API result"`) rather than the read error.

```sh
curl -u fleetcore:$API_KEY -T devicelock.plist "$HOST/v1/enqueue/00008103-001234567890001E?nopush=1"
```

#### `POST /v1/escrowkeyunlock`

Proxies Apple's Activation Lock "escrow key unlock" (bypass code) call, using the APNs push certificate of `topic` for mutual TLS to Apple. Parameters are read from the form body (`application/x-www-form-urlencoded`) despite the code's mix of names for query and form; send them all in the POST body. (Any method reaches the handler, but the form is only parsed for POST/PUT/PATCH.)

| Form field | Required | Notes |
|---|---|---|
| `serial` | yes | Device serial number |
| `productType` | yes | e.g. `iPad4,1` |
| `orgName` | yes | Audit value for Apple |
| `guid` | yes | Audit value: who requests it |
| `escrowKey` | yes | The dash-separated human-readable bypass code |
| `imei`, `imei2`, `meid` | no | Cellular devices only |
| `topic` | yes | APNs topic whose certificate to use |

Response: Apple's status code, headers and body are copied through unchanged.

| Status | When |
|---|---|
| `400` | Missing required fields (`invalid or missing parameters`) or empty `topic` (`{"error": ...}`) |
| `500` | Push certificate not found or the request to Apple failed |
| Apple's | Anything else, passed through |

```sh
curl -u fleetcore:$API_KEY -X POST $HOST/v1/escrowkeyunlock \
  --data-urlencode serial=C02XXXXXXXXX --data-urlencode productType=MacBookPro18,3 \
  --data-urlencode orgName="Example Org" --data-urlencode guid=admin@example.com \
  --data-urlencode escrowKey=ABCD-EFGH-IJKL-MNOP-QRST-UVWX --data-urlencode topic=com.apple.mgmt.External.0000
```

## Events and subscriptions

fleetcore turns changes in its database into events, keeps them for seven days in a log with a sequence number, and lets you read them (a page, a live stream) or subscribe a webhook that is delivered to in order, retried, and replayable. The management API login applies to every endpoint here.

### The event

| Field | Type | |
| --- | --- | --- |
| `seq` | integer | position in the tenant's log; resume from the last one you handled |
| `id` | string | stable for a change however many times it is delivered; ignore repeats |
| `type` | string | see the table |
| `key` | string | the object the event is about |
| `data` | object | identifiers and states only; never profile bodies, command results, tokens or any sealed value |
| `at` | string (RFC 3339) | when the change was made |
| `origin` | string | `fleetcore`, or `fleetcore:<tenant>` |

`GET /v1/events/types` returns the catalog (type, description, what `key` is, the fields of `data`). Types: `enrollment.created`, `enrollment.checkout`, `device.enrolled`, `device.os_changed`, `device.renamed`, `device.supervision_changed`, `device.membership_changed`, `device.deactivated`, `device.lost_mode_changed`, `device.certificate_associated`, `command.queued`, `command.result`, `application.state`, `blueprint.saved`, `blueprint.deleted`, `blueprint.revision`, `group.saved`, `group.deleted`, `vault.access`, `dep.device.assigned`, `dep.device.removed`, `os.release.published`, `schema.updated`, `applicability.changed`, and `test`. A type filter is a list of exact types and prefixes such as `command.*`; `*` or an empty list is everything.

#### `GET /v1/events`

| | |
|---|---|
| Query | `after` (sequence number; events with a larger one), `types` (comma separated filter), `key` (exact), `limit` (default 100, at most 1000) |
| Response | `200` `{"events": [...oldest first], "next": <seq or 0>, "last_seq": <newest in the log>}`; `next` is the cursor for the following page, 0 when there is none |
| Errors | `422` a type filter that matches no type |

#### `GET /v1/events/stream`

Server-Sent Events: each event is `id: <seq>`, `event: <type>`, `data: <event JSON>`. `types` and `key` filter. A new listener sees events from now on; `?after=<seq>` or the `Last-Event-ID` header resumes. A `: keep-alive` comment is sent every 15 seconds.

```sh
curl -N -u fleetcore:$API_KEY 'https://mdm.example.com/v1/events/stream?types=command.*,application.state'
```

### Subscriptions

A subscription is a webhook with a cursor. Each is served on its own, one event at a time in order, so a slow endpoint holds back only itself. A delivery is a `POST` of the event JSON with `X-Fleetcore-Event` (id), `X-Fleetcore-Seq`, `X-Fleetcore-Subscription`, `X-Fleetcore-Timestamp` and `X-Fleetcore-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>" keyed with the subscription's secret>`. Any 2xx advances the cursor. A failure is retried after 2 seconds, doubling up to about 17 minutes; after 25 failures in a row the subscription pauses itself (`state: paused`) until resumed. Redirects are not followed. By default a URL must be `https` and must not resolve to a private, loopback or link-local address, which is checked again on the address actually connected to (`-events-allow-private` lifts both).

| Method and path | |
|---|---|
| `GET /v1/event-subscriptions` | list, each with `state` (active, failing, paused, disabled), `cursor`, `behind` (events not yet delivered), `delivered`, `failures`, `last_error`, `last_success_at`, `next_attempt_at` |
| `POST /v1/event-subscriptions` | create `{"name", "url", "types": [...], "from_seq"}`; it starts at the newest event unless `from_seq` is given. `201` with the subscription and `secret` (`whsec_…`), **shown once** (sealed at rest). `422` for a bad URL or type |
| `GET /v1/event-subscriptions/{id}` | one |
| `PUT /v1/event-subscriptions/{id}` | change `name`, `url`, `types`, `enabled` (any subset) |
| `DELETE /v1/event-subscriptions/{id}` | `204`; its delivery records go too |
| `POST /v1/event-subscriptions/{id}/resume` | clear a pause and the failure count; `204` |
| `POST /v1/event-subscriptions/{id}/replay` | `{"from_seq": N}`: deliver again everything after N (0: all the log keeps); `202` |
| `POST /v1/event-subscriptions/{id}/test` | send a `test` event now and report `{"ok", "status", "millis", "error"}` |
| `GET /v1/event-subscriptions/{id}/deliveries` | the latest attempts (three days kept): `seq`, `event`, `at`, `status`, `ok`, `error`, `millis`; `limit` up to 500 |

```sh
curl -u fleetcore:$API_KEY -X POST https://mdm.example.com/v1/event-subscriptions \
  -d '{"name":"siem","url":"https://siem.example.com/hooks/mdm","types":["vault.access","command.result"]}'
```

Verify a delivery by computing the HMAC over `timestamp + "." + raw body` with the secret and comparing it, in constant time, to the signature; reject old timestamps.

## Metrics

`GET /metrics` serves Prometheus text (OpenMetrics when asked for) and is on unless `-metrics=false` (`FLEETCORE_NO_METRICS`). Login: `Authorization: Bearer <-metrics-token>` for a scraper, or the management API login. Without a token and without a management login the endpoint is absent (404).

**Updated as the process works:**

| Metric | Labels | |
|---|---|---|
| `fleetcore_http_requests_total` | `route`, `method`, `code` | `route` is bounded: known path words kept, identifiers become `{}` |
| `fleetcore_http_request_duration_seconds` (histogram) | `route`, `method` | |
| `fleetcore_http_response_bytes_total`, `fleetcore_http_in_flight_requests` | `route` | |
| `fleetcore_admin_auth_total` | `result` (ok, denied), `method` (key, certificate, none) | |
| `fleetcore_mdm_messages_total`, `fleetcore_mdm_message_duration_seconds` | `type` (Authenticate, TokenUpdate, CheckOut, CommandAndReportResults...), `result` | |
| `fleetcore_mdm_command_reports_total` | `status` | Acknowledged, Error, NotNow, CommandFormatError, Idle |
| `fleetcore_push_notifications_total`, `fleetcore_push_batch_duration_seconds` | `result` (sent, failed) | |
| `fleetcore_blueprint_reconciles_total`, `fleetcore_blueprint_reconcile_duration_seconds` | `result` | |
| `fleetcore_user_authenticate_total` | `result` (challenge, accepted, rejected) | |
| `fleetcore_events_produced_total` | `type` | |
| `fleetcore_event_sink_publishes_total`, `fleetcore_event_sink_publish_duration_seconds` | `sink`, `result` | |
| `fleetcore_event_deliveries_total`, `fleetcore_event_delivery_duration_seconds` | `result`, `status` (2xx, 4xx, 5xx, none) | subscription deliveries |
| `fleetcore_event_subscription_lag_events` | `subscription` | |
| `fleetcore_build_info`, `fleetcore_start_time_seconds`, `go_*`, `process_*` | | |

**Read from MongoDB when scraped** (at most every 15 seconds; each collector timed in `fleetcore_scrape_collector_duration_seconds{collector}` and `fleetcore_scrape_collector_success{collector}`; scoped to the tenant):

| Metric | Labels | |
|---|---|---|
| `fleetcore_enrollments` | `type`, `enabled` | |
| `fleetcore_devices` | `platform`, `active`, `supervised`, `enroll_type` | |
| `fleetcore_devices_by_os_version` | `platform`, `os_version` | the 60 most common, the rest as `other` |
| `fleetcore_devices_os_currency` | `platform`, `state` | current, behind_in_major, current_in_major_newer_major_exists, unknown |
| `fleetcore_devices_not_seen` | `period` (1d, 7d, 30d, 90d) | active devices |
| `fleetcore_devices_by_dep`, `_awaiting_setup`, `_lost_mode` | | |
| `fleetcore_reconcile_queue_due`, `_oldest_due_age_seconds`, `fleetcore_reconcile_leased` | | blueprint work waiting |
| `fleetcore_command_queue` | `status` | Queued, Acknowledged, ... |
| `fleetcore_command_queue_oldest_unanswered_age_seconds`, `fleetcore_command_queue_not_now_repeated` | | |
| `fleetcore_commands_stored` | `request_type` | |
| `fleetcore_blueprints`, `fleetcore_groups`, `fleetcore_blueprint_applications`, `fleetcore_blueprint_applications_given_up` | `enabled`; `kind`; `kind`, `delivery`, `state` | |
| `fleetcore_ddm_declarations`, `_ddm_devices`, `_ddm_status_reports` | | |
| `fleetcore_dep_devices`, `fleetcore_dep_names` | `dep` | |
| `fleetcore_vpp_tokens`, `fleetcore_vpp_licenses` | | |
| `fleetcore_vault_secrets`, `fleetcore_vault_access_24h` | `kind`; `action` | |
| `fleetcore_identity_certificates`, `fleetcore_identity_certificates_expiring` | `state`; `within` (7d, 30d, 90d) | |
| `fleetcore_certificate_expires_in_seconds`, `fleetcore_certificate_expiry_timestamp_seconds` | `kind` (device_identity_ca, apns_push_certificate, dep_access_token, vpp_content_token), `name` | alert on these |
| `fleetcore_user_auth_tokens`, `fleetcore_acme_accounts` | | |
| `fleetcore_event_log_last_sequence`, `_event_log_events`, `_event_log_oldest_age_seconds`, `fleetcore_event_subscriptions`, `fleetcore_event_subscription_delivered_total`, `_consecutive_failures` | `state`; `subscription`, `name` | |
| `fleetcore_schema_snapshot_timestamp_seconds`, `fleetcore_schema_definitions`, `fleetcore_os_releases_refresh_timestamp_seconds`, `fleetcore_os_releases_known`, `fleetcore_os_latest_release_timestamp_seconds` | | Apple's feeds |
| `fleetcore_mongodb_ping_seconds`, `_mongodb_data_bytes`, `_storage_bytes`, `_index_bytes`, `_objects`, `_collections` | | database-wide figures only when the database belongs to one tenant |

`deploy/fleetcore/prometheus-rules.yaml` has alerting rules for certificates about to expire, a stuck reconcile queue, unanswered commands, push failures, failing subscriptions and more.

## What fleetcore calls: events and bridges

fleetcore also makes requests to systems you run. Each is off unless configured.

### Event sinks (`-relay-nats`, `-relay-webhook`)

The event log, its types and the subscription API are in [Events and subscriptions](#events-and-subscriptions). The two sinks below receive every event (or those `-relay-types` selects) as it is produced, in order.

**NATS.** Published to the subject `<prefix>.<type>.<key>` (default prefix `fleetcore.events`; characters NATS reserves in the key, `.` `*` `>` and spaces, become `_`). Core pub/sub unless `-relay-jetstream` is set, in which case each event is a JetStream publish with an acknowledgement and the message id set to `id` (the stream must exist and cover the subjects; JetStream's duplicate window then drops repeats).

**Webhook.** `POST` of the event JSON to `-relay-webhook`, with `Content-Type: application/json`, `X-Fleetcore-Event: <id>` and, when `-relay-webhook-secret` is set, `X-Fleetcore-Timestamp: <unix seconds>` and `X-Fleetcore-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">` (the same scheme as subscriptions; reject a timestamp more than a few minutes old). Any 2xx is success; anything else is retried with a growing pause (half a second, doubling, up to 30 seconds) and later events wait behind it, so order is kept.

**Guarantees.** At least once, in the order of the database's change stream, per tenant. The resume position is saved after each change, so a restart repeats at most the last one. One process per tenant relays at a time (a lease in the database); another takes over when the holder stops.

### MicroMDM-compatible webhook (embedding only)

When it is turned on, `-webhook-url` (`server.Config.WebhookURL`, with `-webhook-hmac-key`) makes the MDM service post every check-in and command report as the MicroMDM-style envelope `EventJson` (`service/webhook`): `topic` (`mdm.Authenticate`, `mdm.TokenUpdate`, `mdm.CheckOut`, `mdm.UserAuthenticate`, `mdm.SetBootstrapToken`, `mdm.GetBootstrapToken`, `mdm.GetToken`, `mdm.DeclarativeManagement`, `mdm.Connect`), `event_id`, `created_at`, and `checkin_event` or `acknowledge_event` (`udid`, `enrollment_id`, `ids`, `raw_payload` base64 of the device's plist, `url_params`, `token_update_tally` on TokenUpdate). Any status other than 200 is an error. With a key, the body is signed in `X-Hmac-Signature` (base64 HMAC-SHA256). The event relay and subscriptions are the richer way to follow what happens.

### UserAuthenticate bridge (`-ua-verify-url`)

When the password is held by a directory fleetcore cannot read, it asks your bridge to check the digest. `POST` to `-ua-verify-url` with `Authorization: Bearer <-ua-verify-secret>` and `Content-Type: application/json`:

```json
{"username": "net1", "realm": "fusion.home", "nonce": "…", "uri": "/", "response": "84db40bb…",
 "qop": "", "nc": "", "cnonce": "", "udid": "23EB7CD8-…", "user_id": "16C0477E-…"}
```

The bridge computes the HTTP digest (RFC 2617: `MD5(MD5(user:realm:password):nonce:MD5(method:uri))`, or the `qop=auth` form when `qop` is set; the method is not published by Apple, so try PUT, POST and GET) and answers `200` with `{"ok": true}` or `{"ok": false}`. Any other status is an error and the user is not authenticated. The request is made only after the nonce was checked as issued to that enrollment and unused.

### Apple services fleetcore calls

| Service | For | Notes |
| --- | --- | --- |
| APNs | push to devices | the push certificate stored with `PUT /v1/pushcert` |
| Apple Business Manager DEP API (`mdmenrollment.apple.com`) | device sync, profile definition and assignment | OAuth tokens stored through `/v1/dep/tokens/{name}` (sealed) |
| Apps and Books API (`vpp.itunes.apple.com`) | licenses | content token stored through `/v1/vpp/tokens/{name}` (sealed) |
| GDMF (`gdmf.apple.com`), the OS releases RSS feed | which OS releases exist and which a device model may take | read hourly; `-no-feeds` uses the built-in snapshot |
| GitHub (`apple/device-management`) | Apple's schemas | read daily; `-no-feeds` uses the built-in snapshot |
| iTunes lookup | the bundle ID of an App Store app | on saving an `app` item with an `adam_id` |

## Behaviors worth knowing

How the code works today; none of these is a recommendation.

- **Enrollment is closed unless you open it.** `/enroll` needs `-enroll-secret`, `-enroll-auth-url` or `-enroll-open`. With `-enroll-open` anyone who can reach the server gets a profile and a one-use SCEP challenge.
- **The API key's user name is ignored,** only the password is checked; named keys (`-api-keys`) give per-caller audit. Use `-admin-ca` for certificate-based callers; both can be required together.
- **Defaults.** `-cert-source` and `server.Config` both default to `tls`.
- **Command status.** `POST /v1/commands` answers `207` when some devices were not queued or not pushed; `result.status.*` says which.
- **Methods.** `/v1/migration` takes PUT or POST; `/v1/enqueue/` PUT or POST; `/v1/push/` GET, PUT or POST. Anything else is `405`.
- **ACME.** `hardware-identifier` orders are refused unless `-acme-allow-unassigned` is set, because only serial numbers are looked up against what Apple assigned.
- **Events need a replica set and change stream access.** A MongoDB login restricted per database must be allowed to open a change stream on its database.
- **Metrics refresh.** The database gauges are at most 15 seconds old; scrape no more often than that for no benefit.
