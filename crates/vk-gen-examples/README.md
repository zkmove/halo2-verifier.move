### Examples

An cli to generate publish-vk aptos transaction payload.


#### Help:

run the following cmd to get a quick start.
```shell
cargo run --release -- --help
```

#### generate publish-vk aptos txn

Run the follow to generate vk info  for circuit in `src/examples/vector-mul.rs`.
replace the `verifier-module` and `verifier-address` with the actual verifier's address and name.
``` shell
cargo run --release -- -k 16 --verifier-module halo2_verifier --verifier-address 0x1234 build-publish-vk-aptos-txn --example vector-mul -o vk_deployment

cargo run --release -- -k 16 --verifier-module halo2_verifier --verifier-address 0x1234 build-publish-vk-aptos-txn --example circuit-layout -o vk_deployment


```
It will generate a json file in dir `vk_deployment`.
#### send the publish-vk transaction

```shell
aptos move run --json-file vk_deployment/VectorMul.json
```

### generate verify-proof aptos txn


Run the follow to generate example proof for circuit in `src/examples/vector-mul.rs`.
replace the `verifier-module` and `verifier-address` with the actual verifier's address and name.
``` shell
cargo run --release -- -k 16 --verifier-module halo2_verifier --verifier-address 0x1234 build-verify-proof-aptos-txn --example vector-mul -o proofs
```
