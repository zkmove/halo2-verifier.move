# Overview

The project is a halo2 zk-proofs verifier written in Move language. It provides on-chain verification api, helper utilities, and SDK tooling for verifying halo2 proofs on any Move blockchains.

It supports two verifier variants:
- A pure Move verifier for maximum portability.
- A fast verifier backed by native functions for higher performance.

Key components:

Move packages (per-chain variants for Aptos and Sui):
- `packages/common-*`: shared low-level utilities, such as BN254 field/curve arithmetic and byte (de)serialization helpers.
- `packages/verifier-*`: the core on-chain halo2 verifier implementation (transcript, multi-open scheme, pairing checks), including both the pure Move and native-backed variants.
- `packages/api-*`: public-facing Move entry APIs for publishing KZG params, verification keys, and circuit descriptions on chain, and for invoking proof verification.

Rust crates (off-chain SDK and tooling):
- `crates/halo2`: thin wrapper around the upstream halo2 proving stack, providing KZG/SHPLONK proof generation and local verification helpers.
- `crates/halo2-circuit-info`: custom serialization for the Halo2 circuit environment, where all field elements are replaced with indices pointing to a constant table. 
- `crates/halo2-verifier`: the Rust verification backend for the native verifier. It reconstructs the constraint system and verification key from the serialized circuit info, and performs the actual proof verification that the on-chain native functions delegate to.
- `crates/aptos-verifier-api` / `crates/sui-verifier-api`: chain-specific SDKs that build the transactions (entry-function payloads / PTBs) for publishing params, VKs, and circuits, and for submitting proof verification.
- `crates/sui-ptb-helper`: utilities for constructing and signing Sui programmable transaction blocks used by the Sui tooling.
- `crates/vk-gen-examples`: example circuits and generators producing sample proofs, verification keys, and public inputs for end-to-end testing.

Other directories:
- `example/`: a runnable Move example (fibonacci circuit) with prebuilt params, proofs, and witnesses.
- `scripts/`: shell scripts for localnet end-to-end runs and uploading artifacts/proofs.

See [TUTORIAL.md](./TUTORIAL.md) for step-by-step usage and workflows.
