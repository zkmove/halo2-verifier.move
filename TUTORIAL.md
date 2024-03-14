### Tutorial on halo2-verifier

This doc will guide you through the usage of halo2-verifier.

Cli `aptos` is necessary for the tutorial, make sure you download it from https://github.com/aptos-labs/aptos-core/releases. 
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
cargo run --release -- --param-path params/kzg_bn254_16.srs view-param
```

We have to send a  create-params transcation to make the params available on aptos.
Copy paste the `g1`, `g2`, `s_g2` as aptos args, resulting the following aptos command: 
```shell
aptos move run --function-id default::param_store::create --args hex:0x0100000000000000000000000000000000000000000000000000000000000000 hex:0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19 hex:0x0016e2a0605f771222637bae45148c8faebb4598ee98f30f20f790a0c3c8e02a7bf78bf67c4aac19dcc690b9ca0abef445d9a576c92ad6041e6ef1413ca92a17
```

Then, we are ready to publish a circuit!
We're going to use example `vector-mul` in our vk-gen-examples.
Enter directory `crates/vk-gen-examples`, and run the cargo command, remember **replace the verifier-address with your aptos profile's address!**
```shell
cargo run --release -- --param-path params/kzg_bn254_16.srs --verifier-address 0xcfae5b6bd579e7aff4274aeca434bb500c024b89c139b545c6eeb27bfafea8c1 build-publish-vk-aptos-txn --example vector-mul
```
It will output a json file which you can take as input to `aptos move run`.

```shell
aptos move run --json-file VectorMul-publish-circuit.json
```

Now, the circuit is published. We'll build a verify proof aptos txn and run it on aptos. 
Run the command and replace the `verifier-address`/`param-address`/`circuit-address` with your aptos profile's address!
```shell
cargo run --release -- --param-path params/kzg_bn254_16.srs --verifier-address 0xcfae5b6bd579e7aff4274aeca434bb500c024b89c139b545c6eeb27bfafea8c1 build-verify-proof-aptos-txn --param-address 0xcfae5b6bd579e7aff4274aeca434bb500c024b89c139b545c6eeb27bfafea8c1 --circuit-address 0xcfae5b6bd579e7aff4274aeca434bb500c024b89c139b545c6eeb27bfafea8c1  --example vector-mul --kzg gwc 
```

Then, submit the verify proof txn, you can see the verify txn is executed successfully.

```shell
aptos move run --json-file VectorMul-verify-proof-gwc.json
```

Finally! That's the whole experiment with halo2-verifier!

You can also use the [verifier sdk](crates/verifier-sdk) of rust to generate aptos txn payload, and use it freely in your own code!

More features are coming!
