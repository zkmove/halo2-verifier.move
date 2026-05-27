# Overview

The project is a halo2 zk-proofs verifier written in Move language. It provides on-chain verification api, helper utilities, and SDK tooling for verifying halo2 proofs on any Move blockchains.

It supports two verifier variants:
- A pure Move verifier for maximum portability.
- A fast verifier backed by native functions for higher performance.

Key components:
- `packages/common-aptos`: shared Aptos Move utilities (e.g., field/serialization helpers).
- `packages/verifier-aptos`: the core Aptos verifier implementation.
- `packages/api-aptos`: public-facing Aptos Move APIs and integration helpers.
- `packages/common-sui`: shared Sui Move utilities.
- `packages/verifier-sui`: the core Sui verifier implementation.
- `packages/api-sui`: public-facing Sui Move APIs and integration helpers.
- `crates/*`: Rust tooling that supports the verifier (serialization/deserialization, SDK helpers, and examples).

## Aptos

The Aptos Move packages live under the `*-aptos` directories:

- `packages/common-aptos`
- `packages/verifier-aptos`
- `packages/api-aptos`

Use [TUTORIAL.md](./TUTORIAL.md) for the Aptos localnet workflow. The helper scripts under `scripts/*_aptos.sh` and [publish_contracts.sh](./publish_contracts.sh) also target these Aptos package directories.

## Sui

The Sui Move packages live under the `*-sui` directories:

- `packages/common-sui`
- `packages/verifier-sui`
- `packages/api-sui`

`packages/verifier-sui` contains the pure Move verifier port for Sui and depends on `packages/common-sui`. `packages/api-sui` exposes Sui-facing verifier APIs and object-builder entry points for publishing large verifier artifacts across multiple programmable transaction blocks.

Useful Sui entry points:

- [packages/verifier-sui/README.md](./packages/verifier-sui/README.md): verifier package status and test command.
- [packages/api-sui/examples/chunked_publish_ptb.md](./packages/api-sui/examples/chunked_publish_ptb.md): chunked artifact upload and finalize flow.
- [scripts/localnet_e2e.sh](./scripts/localnet_e2e.sh): Sui localnet end-to-end flow for publishing the API package and exercising example dapp verifier paths.
