# Overview

The project is a halo2 verifier written in Move language. It provides on-chain verification logic, helper utilities, and SDK tooling for verifying halo2 proofs on chain.

It supports two verifier variants:
- A pure Move verifier for maximum portability.
- A fast verifier backed by native functions for higher performance.

Key components:
- `packages/common`: shared Move utilities (e.g., field/serialization helpers).
- `packages/verifier`: the core Move verifier implementation.
- `packages/api`: public-facing Move APIs and integration helpers.
- `crates/*`: Rust tooling that primarily supports the fast native verifier (serialization, SDK helpers, and examples).

See [TUTORIAL.md](./TUTORIAL.md) for step-by-step usage and workflows.
