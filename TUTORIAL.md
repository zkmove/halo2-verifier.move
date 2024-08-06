# Tutorial on halo2-verifier

This doc will guide you through the usage of halo2-verifier.

Cli `aptos` is necessary for the tutorial, make sure you download it from <https://github.com/aptos-labs/aptos-core/releases>.
Also, the repo is an essence.

First, let's create an aptos profile on aptos devnet.
Execute the command under the project root. It will generate config file of aptos account in `.aptos/config.yaml`.

``` shell
aptos init --network devnet
```

Next, we need to publish the halo2-verifier & halo2-common modules to aptos devnet under the new-generated profile account.
The following commands will use aptos cli to compile and publish the three packages: `common`, `verifier` and `api`.
When first executing, it will fetch dependencies, which may need a little time. so be patient here.

``` shell
cd packages/common
aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_common=default
cd ../verifier
aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_common=default,halo2_verifier=default
cd ../api
aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_common=default,halo2_verifier=default,verifier_api=default
```

Then, we can start to publish our circuit to chain ready for use in halo2-verifier.

But first, we need a params of kzg setup. There exists a setup called [Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) hold by pse.
We're going to use a version of axiom.
the existing param file `crates/vk-gen-examples/params/challenge_0078-kzg_bn254_16.srs` is downloaded from [axiom page](https://docs.axiom.xyz/transparency-and-security/kzg-trusted-setup).

To view the kzg setup params, run the following cargo commands under directory `crates/vk-gen-examples`.
It will output the g1, g2, and s_g2.

```shell
cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs view-param
```

We have to send a  create-params transcation to make the params available on aptos.
Copy paste the `g1`, `g2`, `s_g2` as aptos args, resulting the following aptos command:

```shell
aptos move run --function-id default::param_store::create --args hex:0x0100000000000000000000000000000000000000000000000000000000000000 hex:0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19 hex:e4115200acc86e7670c83ded726335def098657fe8668323e9e41e6781b83b0a9d83b54bbb00215323ce6d7f9d7f331a286d7707d03f7dbdd3125c6163588d13
```

Then, we are ready to publish a circuit!
We're going to use example `vector-mul` in our vk-gen-examples.
Enter directory `crates/vk-gen-examples`, and run the cargo command, remember **replace the verifier-address with your aptos profile's address!**

```shell
cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b build-publish-vk-aptos-txn --example vector-mul
```

It will output a json file which you can take as input to `aptos move run`.

```shell
aptos move run --json-file VectorMul-publish-circuit.json
```

Now, the circuit is published. We'll build a verify proof aptos txn and run it on aptos.
Run the command and replace the `verifier-address`/`param-address`/`circuit-address` with your aptos profile's address!

```shell
cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b build-verify-proof-aptos-txn --example vector-mul --kzg gwc --param-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b --circuit-address c9666cf9a032e81737eb706ce538a423706d86a2a502027fbc909e0817bf313b
```

Then, submit the verify proof txn, you can see the verify txn is executed successfully.

```shell
aptos move run --json-file VectorMul-verify-proof-gwc.json
```

Finally! That's the whole experiment with halo2-verifier!

You can also use the [verifier sdk](crates/verifier-sdk) of rust to generate aptos txn payload, and use it freely in your own code!

More features are coming!
