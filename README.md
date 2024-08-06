# halo2 verifier in Move

The project is a halo2 verifier written in Move language.
Its objective to enhance the capability of the blockchains in the Move ecosystem by enabling halo2 zero-knowledge proofs to be verified on-chain.

## Why the project

Halo2 is a widely used plonk implementation. zcash, scroll, axiom, taiko and many other famous projects are developed based on halo2.
There exists a general verification process for different circuits in rust,
however, blockchains cannot utilize the code directly because of the gap in the language or api.
several organizations are developing onchain verifiers(like [halo-solidity-verifier](https://github.com/privacy-scaling-explorations/halo2-solidity-verifier)) in solidity for EVM communities,
although it’s not a general verifier code, only a general template generator.
One still needs to generate a verifier contract for each circuit sharing most of the code.

halo2-verifier.move uses a different approach, it tries to extract the information of a halo2 circuit, and abstract them out into a `Protocol` of the circuit(we call it the shape of a circuit), circuit’s shape includes:

- Gates. Mainly the constraints you write in the circuit.
- [Lookup arguments](https://zcash.github.io/halo2/design/proving-system/lookup.html). include the input expressions and table expressions.
- Queries on each columns.
- Commitments of fixed columns and [permutations](https://zcash.github.io/halo2/design/proving-system/permutation.html).
- Other necessary informations like, `k`, `cs_degree`, `num_of_fixed_columns`.

With these information, the general verifier can read commitments and evaluations in proofs of the circuit, and do verification accordingly using a polynomial commitment scheme.

## Give it a try

See [TUTORIAL.md](./TUTORIAL.md).
