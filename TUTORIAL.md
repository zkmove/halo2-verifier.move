# Tutorial on halo2-verifier

This guide explains how to use the Aptos on-chain halo2 verifier from `packages/*-aptos`. Before you start, make sure you have go through the `Tutorial on zkMove CLI` to get familiar with zkMove CLI and have a proof for the example circuit generated.

## Install `aptos` CLI

Download the Aptos CLI from <https://github.com/zkmove/aptos-core/releases/download/aptos-cli-v7.11.1-zkmove>.

On macOS, the file name looks like `aptos-cli-<version>-macOS-arm64.zip`. Choose the correct architecture (x86_64 or arm64).
Unzip the file, move the binary to a preferred location, and make it executable:

```shell
chmod +x ~/aptos
```

Verify the installation:

```shell
~/aptos help
```

## Start DevNet

Start a local network (see <https://aptos.dev/network/nodes/localnet/local-development-network#starting-a-local-network>).

Create three local profiles at the project root:

```shell
# Create account profile for publish contracts under it
aptos init --profile <your-profile-for-contracts> --network local
# Create account profile for publish params under it
aptos init --profile <your-profile-for-params> --network local
# Create account profile for create verifier under it
# We specifically separate this from params publishing because each circuit has its own verifier but they can share the same params.
aptos init --profile <your-profile-for-verifier> --network local
```

This creates account in `.aptos/config.yaml`. You can check the account addresses with:
```shell
aptos config show-profiles --profile <your-profile-for-contracts>
```

Fund the accounts with faucet:
```shell
aptos account fund-with-faucet --url http://127.0.0.1:8080 --amount 5000000000000000000 --profile <your-profile-for-contracts>
aptos account fund-with-faucet --url http://127.0.0.1:8080 --amount 5000000000000000000 --profile <your-profile-for-params>
aptos account fund-with-faucet --url http://127.0.0.1:8080 --amount 5000000000000000000 --profile <your-profile-for-verifier>
```

## Publish verifier contracts

Run the script to publish the verifier contracts to the local network:
```shell
# Run in the project root
PROFILE=<your-profile-for-contracts> ./publish_contracts.sh
```

## Deploy verifier for specific circuit

Two verifier variants are available:
- Native: uses native functions for faster verification.
- Pure Move: implements verification entirely in Move, offering better portability.

This section deploys the native verifier first, and then deploys the pure move verifier as an option. We use the Fibonacci circuit (project_root/examples/fibonacci) as an example to show how to deploy the verifier.

### Deploy the native halo2 verifier

Publish KZG params:

```shell
zkmove aptos build-publish-params-native-aptos-txn --params-path example/params/kzg_bn254_12.srs --params-contract-address <address-of-your-profile-for-contracts>
```

Run the generated transaction, which publishes the KZG SRS under the account of <your-profile-for-params>.

```shell
aptos move run --json-file kzg_bn254_12-publish-params-native.txn --profile <your-profile-for-params>
```

Publish the circuit and verifying key under the account of <your-profile-for-verifier>:

```shell
# `-p` flag specifies the path to the circuit package, which must contain a `Move.toml` file.
zkmove aptos build-publish-circuit-native-aptos-txn --params-path example/params/kzg_bn254_12.srs -p example --circuit-name fibonacci -w example/witnesses/test_fibonacci-1747793629098.json --native-verifier-contract-address <address-of-your-profile-for-contracts>
```

This generates two transactions:
- `test_fibonacci-1747793629098-publish-vk-native.txn`
- `test_fibonacci-1747793629098-publish-circuit-native.txn`

Run them in order:

```shell
aptos move run --json-file test_fibonacci-1747793629098-publish-vk-native.txn --profile <your-profile-for-verifier>
aptos move run --json-file test_fibonacci-1747793629098-publish-circuit-native.txn --profile <your-profile-for-verifier>
```

###  (Optional) Deploy the pure move verifier

Publish KZG params:

```shell
zkmove aptos build-publish-params-aptos-txn --params-path example/params/kzg_bn254_12.srs --params-contract-address <address-of-your-profile-for-contracts>
```

Run the generated transaction:

```shell
aptos move run --json-file kzg_bn254_12-publish-params.txn  --profile <your-profile-for-params>
```

Publish the circuit:

```shell
zkmove aptos build-publish-circuit-aptos-txn --params-path example/params/kzg_bn254_12.srs -p ./example --circuit-name fibonacci -w example/witnesses/test_fibonacci-1747793629098.json  --verifier-contract-address <address-of-your-profile-for-contracts>
```

Run the generated transaction:

```shell
aptos move run --json-file test_fibonacci-1747793629098-publish-circuit.txn  --profile <your-profile-for-verifier>
```

## Verify proof on-chain

Assume you have generated the proof for the Fibonacci circuit with zkMove CLI and have the following files:
- `example/proofs/test_fibonacci-1754384516414.instance`
- `example/proofs/test_fibonacci-1754384516414.proof`

Build a verify-proof transaction for the native verifier:

```shell
# Replace `<your_parameter_k>` with the actual parameter k used when generating the proof.
zkmove aptos build-verify-proof-native-aptos-txn --pubs-path example/proofs/test_fibonacci-1754384516414.instance --proof-path example/proofs/test_fibonacci-1754384516414.proof --k <your_parameter_k> --native-verifier-contract-address <address-of-your-profile-for-contracts> --params-address <address-of-your-profile-for-params> --native-verifier-address <address-of-your-profile-for-verifier>
```

Submit the verify-proof transaction (any user can submit the transaction):

```shell
aptos move run --json-file test_fibonacci-1747793629098-verify-proof-native.txn --profile <any-profile>
```

Or, build a verify-proof transaction for the pure Move verifier:

```shell
zkmove aptos build-verify-proof-aptos-txn --pubs-path example/proofs/test_fibonacci-1754384516414.instance --proof-path example/proofs/test_fibonacci-1754384516414.proof --verifier-contract-address <address-of-your-profile-for-contracts> --params-address <address-of-your-profile-for-params> --verifier-address <address-of-your-profile-for-verifier>
```
Submit the transaction:

```shell
aptos move run --json-file test_fibonacci-1747793629098-verify-proof.txn --profile <any-profile>
```
