# NanoMDM

[![CD/CD](https://github.com/micromdm/nanomdm/actions/workflows/on-push-pr.yml/badge.svg)](https://github.com/micromdm/nanomdm/actions/workflows/on-push-pr.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/micromdm/nanomdm.svg)](https://pkg.go.dev/github.com/micromdm/nanomdm)

NanoMDM is a minimalist [Apple MDM](https://developer.apple.com/documentation/devicemanagement) server and library heavily inspired by [MicroMDM](https://github.com/micromdm/micromdm).

## fleetcore

This fork also contains **fleetcore**, a complete, standalone Apple MDM in one Go binary on MongoDB. It needs a MongoDB replica set, an Apple push certificate and a public HTTPS name, and nothing else. Any product can manage it through its HTTP API.

- **Enrollment:** a SCEP certificate authority, enrollment profiles, TLS (or a proxy in front), Automated Device Enrollment (ADE/DEP) with signed device requests and await-configuration, account-driven User Enrollment (BYOD) with `GetToken`, and hardware-bound identities by ACME with Apple device attestation.
- **Configuration:** blueprints (desired state with scope rules, groups and staged rollouts), declarative device management first (configurations, activations, assets, predicates, status, software update enforcement) with profiles as the fallback, platform- and OS-aware payloads that follow Apple's published schemas and OS releases as they change, and a translator from profiles to declarations (with a coverage report).
- **Operations:** a JSON command API over all of Apple's commands, device, enrollment and command-queue listings with cursors, workflows (Lost Mode, Activation Lock bypass, FileVault key rotation, recovery lock, bootstrap token) with an audited secret vault, Apps and Books (VPP) licensing and `InstallApplication`, Platform SSO items, `UserAuthenticate` for network and mobile users, an event relay to NATS or a signed webhook, and migration from NanoMDM-family servers and device import from other MDMs.
- **Security and tenancy:** per-tenant sealing of secrets with tenant-held keys, certificate login to MongoDB with one database per tenant identity, a mutual-TLS management API, and a build-time and runtime check that every query on a shared collection is scoped to its tenant.

```sh
docker run --rm fleetcore keygen            # a master key; keep it somewhere safe
FLEETCORE_URL=https://mdm.example.com \
FLEETCORE_API_KEY=$(openssl rand -hex 32) \
FLEETCORE_MASTER_KEY=<the key> \
docker compose -f deploy/fleetcore/compose.yaml up --build
```

See [docs/fleetcore.md](docs/fleetcore.md) (running it, configuration, tenancy, every feature), [docs/api-reference.md](docs/api-reference.md) (every endpoint) and [docs/fleetcore-roadmap.md](docs/fleetcore-roadmap.md) (what is built and what is not). Nothing in fleetcore has yet been run against real devices, Apple Business Manager or the App Store.

## Getting started & Documentation

- [Quickstart](docs/quickstart.md)  
A quick guide to get NanoMDM up and running using ngrok.

- [Operations Guide](docs/operations-guide.md)  
A brief overview of the various command-line switches and HTTP endpoints and APIs available to NanoMDM.

## Getting the latest version

* Release `.zip` files containing the server and supplementals should be attached to every [GitHub release](https://github.com/micromdm/nanomdm/releases).
  * Release zips are also [published](https://github.com/micromdm/nanomdm/actions) for every `main` branch commit.
* A Docker container is built and [published to the GHCR.io](http://ghcr.io/micromdm/nanomdm) registry for every release.
  * `docker pull ghcr.io/micromdm/nanomdm:latest` — `docker run ghcr.io/micromdm/nanomdm:latest`
  * A Docker container is also published for every `main` branch commit (and tagged with `:main`)
* If you have a [Go toolchain installed](https://go.dev/doc/install) you can checkout the source and simply run `make`.

## Features

- Horizontal scaling: zero/minimal local state. Persistence in storage layers. MySQL, PostgreSQL and MongoDB backends provided in the box (this fork adds MongoDB).
- Multiple APNs topics: potentially multi-tenant.
- Multi-command targeting: send the same command (or pushes) to multiple enrollments without individually queuing commands.
- Migration endpoint: allow migrating MDM enrollments between storage backends or (supported) MDM servers
- Otherwise we share many features between MicroMDM and NanoMDM, such as:
  - A MicroMDM-emulating HTTP webhook/callback.
  - Enrollment-certificate authorization
  - API-driven interaction (queuing of commands, APNs pushes, etc.)

## What upstream NanoMDM leaves out, and where fleetcore has it

NanoMDM is one component of an MDM. On its own it does not include the pieces below; each is built into fleetcore. If you use NanoMDM as a library without fleetcore, you still bring your own.

| Not in NanoMDM | In fleetcore |
| --- | --- |
| SCEP | a CA made on first start, SCEP at `/scep` (`fleetcore/pki`) |
| TLS | its own listener (certificate or Let's Encrypt), or a proxy in front |
| Enrollment profiles | `/enroll`, `/enroll/ade`, `/enroll/byod` (`fleetcore/enroll`, `fleetcore/byod`) |
| ADE (DEP) API access | `fleetcore/dep`: tokens, sync, assigner, profile definition |
| Blueprints | `fleetcore/blueprints`: scope rules, groups, staged rollouts, drift repair |
| JSON command API | `/v1/commands`, validated against Apple's schemas |
| VPP | `fleetcore/vpp`: licensing and `InstallApplication` |
| Enrollment and device APIs | `/v1/devices`, `/v1/enrollments`, `/v1/queue`, with cursors |

## Architecture Overview

NanoMDM, at its core, is a thin composable layer between HTTP handlers and a set of storage abstractions.

- The "front-end" is a set of standard Golang HTTP handlers that handle MDM and API requests. The core MDM handlers adapt the requests to the service layer. These handlers exist in the `http` package.
- The service layer is a composable interface for processing and handling MDM requests. The main NanoMDM service dispatches to the storage layer. These services exist under the `service` package.
- The storage layer is a set of interfaces and implementations that store & retrieve MDM enrollment and command data. These exist under the `storage` package.

You can read more about the architecture in the blog post [Introducing NanoMDM](https://micromdm.io/blog/introducing-nanomdm/).
