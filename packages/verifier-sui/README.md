# halo2-verifier-sui

Sui Move port of the pure Move Halo2 verifier.

This package is intentionally separate from `packages/verifier-aptos`, which remains the Aptos verifier package. The Sui port depends on `packages/common-sui` and the local Sui framework.

## Current migration status

Ported:

- `evaluator.move`
- `transcript.move`
- `protocol.move`
- `vanishing.move`
- `permutation.move`
- `lookup.move`
- `shuffle.move`
- `gwc.move`
- `shplonk.move`
- `halo2_verifier.move`

Planned next modules:

- None. The pure Move verifier module set has been ported; remaining work is fixture parity and downstream API wiring.

## Run tests

```bash
cd /Users/greg/work/halo2-verifier.move/packages/verifier-sui
PATH=/Users/greg/work/sui/target/debug:$PATH sui move test
```

## Notes

- `packages/common-sui` owns the Sui BN254/common helper modules.
- The package should not depend on Aptos framework modules.
- The public API should stay close to the Aptos verifier so downstream ports can be incremental.
- Sui reserves module `init` functions, so `transcript.move` uses `transcript::new` instead of Aptos `transcript::init`.
