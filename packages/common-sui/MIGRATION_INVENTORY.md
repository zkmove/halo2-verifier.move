# common-sui migration inventory

This document tracks the cleanup-first migration from `packages/common` to `packages/common-sui`.

## Ported

- `bn254_serialize.move`
- `bn254_utils.move`

## Phase 1: pure Move modules

These modules have no Aptos-only crypto dependencies and should be ported first:

- `i32.move`
- `vec_utils.move`
- `column.move`
- `column_query.move`

## Deferred: Sui BN254 / verifier math modules

These modules are live in the Aptos verifier/API and should be ported after Phase 1:

- `serialized_public_inputs.move`
- `public_inputs.move`
- `params.move`
- `msm.move`
- `query.move`
- `domain.move`
- `plain_keccak.move`

## Not currently ported

- `plain_blake2b.move`: no current downstream Move references were found. Keep it out of `common-sui` unless a Sui transcript path needs Blake2b later.

## Notes

- Keep `packages/common` intact while Aptos packages still depend on it.
- Prefer Sui-native APIs in `common-sui`, especially `sui::bn254` and `sui::group_ops`.
- Preserve byte layouts for public inputs and BN254 serialization.
