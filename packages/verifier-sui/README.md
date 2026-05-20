# halo2-verifier-sui

Sui Move port of the pure Move Halo2 verifier.

This package is intentionally separate from `packages/verifier`, which remains the Aptos verifier package. The Sui port depends on `packages/common-sui` and the local Sui framework.

## Current migration status

Ported:

- `evaluator.move`

Planned next modules:

- `transcript.move`
- `protocol.move`
- `vanishing.move`
- `permutation.move`
- `lookup.move`
- `shuffle.move`
- `gwc.move`
- `shplonk.move`
- `halo2_verifier.move`

## Run tests

```bash
cd /Users/greg/work/halo2-verifier.move/packages/verifier-sui
PATH=/Users/greg/work/sui/target/debug:$PATH sui move test
```

## Notes

- `packages/common-sui` owns the Sui BN254/common helper modules.
- The package should not depend on Aptos framework modules.
- The public API should stay close to the Aptos verifier so downstream ports can be incremental.
