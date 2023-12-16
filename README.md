## halo2 verifier in Move

### Compile

- on aptos, run: `aptos move compile --dev`

### Profiling

1. Start a aptos node with the cli built from aptos source code containing bn254 feature. `aptos node run-local-testnet`
2. Generate an aptos profile with `aptos init` , notice: use local mode.
3. Publish modules and build the example scripts. `aptos move publish --skip-fetch-latest-git-deps --override-size-check --named-addresses halo2_verifier=your-address`
4. Run profiling. `aptos move run-script --profile-gas --compiled-script-path build/halo2-verifier/bytecode_scripts/verify_example.mv`
5. open the page under `gas-profiling/` directory.


### Give it a try

``` shell

# create aptos profile in `.aptos/config.yaml`
aptos init --network devnet

aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_verifier=default
aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_verifier=default,verifier_api=default

# view kzg setup params, it will output the g1, g2, and s_g2
cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs
# create kzg params, copy paste the g1, g2, s_g2 as aptos args
aptos move run --function-id default::param_store::create --args hex:0x0100000000000000000000000000000000000000000000000000000000000000 hex:0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19 hex:e4115200acc86e7670c83ded726335def098657fe8668323e9e41e6781b83b0a9d83b54bbb00215323ce6d7f9d7f331a286d7707d03f7dbdd3125c6163588d13

# build publish-circuit aptos txn. replace the verifier-address with your aptos profile's address! 
cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b build-publish-vk-aptos-txn --example vector-mul

# run the aptos txn
aptos move run --json-file VectorMul-publish-circuit.json

# build verify proof aptos txn. replace the verifier-address/param-address/circuit-address with your aptos profile's address!
cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b build-verify-proof-aptos-txn --example vector-mul --param-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b --circuit-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b

# submit verify proof txn, you can see the verify txn is executed successfully.
aptos move run --json-file VectorMul-verify-proof.json

```