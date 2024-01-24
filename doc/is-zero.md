# is-zero

Please implement a is-zero circuit based on Halo2. for example:

- case 1: input == 0, then output is 1(True) 
- case 2: input == 2, then output is 0(False)

### halo2-verifier.move

Let's take advantage of an on-chain plonk verifier for Halo2 circuit([halo2-verifier.move](https://github.com/zkmove/halo2-verifier.move/)). So please work based on it.

**Code MUST be placed within `crates/vk-gen-examples/src/examples/is_zero.rs`**.

There is an example: `crates/vk-gen-examples/src/examples/simple_example.rs`

### Trace log

Please read carefully the [tutorial document](https://github.com/luxebeng/halo2-question/blob/main/TUTORIAL.md).

Below is the trace log on how to verify based on halo2-verifier.move.

- Step 1. Create aptos profile. 

```
❯ aptos init --network devnet
Configuring for profile default
Configuring for network Devnet
Enter your private key as a hex literal (0x...) [Current: None | No input: Generate new key (or keep one if present)]

No key given, generating key...
Account 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 doesn't exist, creating it and funding it with 100000000 Octas
Account 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 funded successfully

---
Aptos CLI is now set up for account 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 as profile default!  Run `aptos --help` for more information about commands
{
  "Result": "Success"
}
```

- Step 2. Publish packages.

```
❯ cd packages/common
❯ aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_common=default --assume-yes

Compiling, may take a little while to download git dependencies...
INCLUDING DEPENDENCY AptosFramework
INCLUDING DEPENDENCY AptosStdlib
INCLUDING DEPENDENCY MoveStdlib
BUILDING halo2-common
package size 22502 bytes
{
  "Result": {
    "transaction_hash": "0x1ec3dad3fb9e36561f23ffa076ec3374fbb83aad6884d18e59982cf9cc6453a0",
    "gas_used": 18293,
    "gas_unit_price": 100,
    "sender": "b3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88",
    "sequence_number": 0,
    "success": true,
    "timestamp_us": 1706001618866261,
    "version": 2823602,
    "vm_status": "Executed successfully"
  }
}

❯ cd ../verifier
❯ aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_common=default,halo2_verifier=default --assume-yes

Compiling, may take a little while to download git dependencies...
INCLUDING DEPENDENCY AptosFramework
INCLUDING DEPENDENCY AptosStdlib
INCLUDING DEPENDENCY MoveStdlib
INCLUDING DEPENDENCY halo2-common
BUILDING halo2-verifier
package size 47726 bytes
{
  "Result": {
    "transaction_hash": "0xbc2ed5644a5a896dec802a29aacf2ce2431bcf3bea9806f5666e79f31898c0ef",
    "gas_used": 38658,
    "gas_unit_price": 100,
    "sender": "b3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88",
    "sequence_number": 1,
    "success": true,
    "timestamp_us": 1706001645879590,
    "version": 2823786,
    "vm_status": "Executed successfully"
  }
}

❯ cd ../api
❯ aptos move publish --skip-fetch-latest-git-deps --named-addresses halo2_common=default,halo2_verifier=default,verifier_api=default --assume-yes

Compiling, may take a little while to download git dependencies...
INCLUDING DEPENDENCY AptosFramework
INCLUDING DEPENDENCY AptosStdlib
INCLUDING DEPENDENCY MoveStdlib
INCLUDING DEPENDENCY halo2-common
INCLUDING DEPENDENCY halo2-verifier
BUILDING verifier-api
package size 3512 bytes
{
  "Result": {
    "transaction_hash": "0x9b8d9bccacdf2b43f534e9b024e126dc79115a73ad93b9293fa3d962845e8bc0",
    "gas_used": 17262,
    "gas_unit_price": 100,
    "sender": "b3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88",
    "sequence_number": 2,
    "success": true,
    "timestamp_us": 1706001786330041,
    "version": 2824759,
    "vm_status": "Executed successfully"
  }
}

❯ cd ../..
```

- Step 3. View kzg setup params, it will output the g1, g2, and s_g2.

```
❯ cd crates/vk-gen-examples

❯ cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs view-param

    Finished release [optimized] target(s) in 0.63s
     Running `target/release/vk-gen-examples --param-path params/challenge_0078-kzg_bn254_16.srs view-param`
param info:
halo2 encoding,
k: 16
g: 0100000000000000000000000000000000000000000000000000000000000000
g2: edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19
s_g2: e4115200acc86e7670c83ded726335def098657fe8668323e9e41e6781b83b0a9d83b54bbb00215323ce6d7f9d7f331a286d7707d03f7dbdd3125c6163588d53

arkworks encoding,
k: 16
g: 0100000000000000000000000000000000000000000000000000000000000000
g2: edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19
s_g2: e4115200acc86e7670c83ded726335def098657fe8668323e9e41e6781b83b0a9d83b54bbb00215323ce6d7f9d7f331a286d7707d03f7dbdd3125c6163588d13

❯ cd ../..
```

- Step 4. Create kzg params, copy paste the `g1`, `g2`, `s_g2` of arkworks encoding as aptos args.

```
❯ aptos move run --function-id default::param_store::create --args hex:0100000000000000000000000000000000000000000000000000000000000000 hex:edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19 hex:e4115200acc86e7670c83ded726335def098657fe8668323e9e41e6781b83b0a9d83b54bbb00215323ce6d7f9d7f331a286d7707d03f7dbdd3125c6163588d13 --assume-yes

{
  "Result": {
    "transaction_hash": "0x72231abc8abed1d910115aa8ed6bb446e1a990edc38fb6bdbd5b2f4033771651",
    "gas_used": 534,
    "gas_unit_price": 100,
    "sender": "b3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88",
    "sequence_number": 3,
    "success": true,
    "timestamp_us": 1706002087035861,
    "version": 2826796,
    "vm_status": "Executed successfully"
  }
}
```

- Step 5. Build circuit of **is_zero**.

```
❯ cd crates/vk-gen-examples
❯ cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 build-publish-vk-aptos-txn --example is-zero

    Finished release [optimized] target(s) in 0.30s
     Running `target/release/vk-gen-examples --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 build-publish-vk-aptos-txn --example is-zero`

❯ cd ../..
```
there is a file `IsZero-publish-circuit.json` generated.

- Step 6. Run aptos txn to publish on chain.

```
❯ aptos move run --json-file crates/vk-gen-examples/IsZero-publish-circuit.json --assume-yes

{
  "Result": {
    "transaction_hash": "0x9a5863b41aa30bf3e2ba86086009a87b6ea94fc2f11dd6b9bdcf5c03a21476a1",
    "gas_used": 654,
    "gas_unit_price": 100,
    "sender": "b3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88",
    "sequence_number": 4,
    "success": true,
    "timestamp_us": 1706002338383802,
    "version": 2828532,
    "vm_status": "Executed successfully"
  }
}
```

- Step 7. Build verify proof aptos txn.

```
❯ cd crates/vk-gen-examples
❯ cargo run --release -- --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 build-verify-proof-aptos-txn --example is-zero --kzg shplonk --param-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 --circuit-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88

    Finished release [optimized] target(s) in 0.25s
     Running `target/release/vk-gen-examples --param-path params/challenge_0078-kzg_bn254_16.srs --verifier-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 build-verify-proof-aptos-txn --example is-zero --param-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 --circuit-address 0xb3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88 --kzg shplonk`
proof size 736 bytes
prove time: 3164 ms
verify time: 5 ms

❯ cd ../..
```

- Step 8. Submit verify proof txn, you can see the verify txn is executed successfully.

```
❯ aptos move run --json-file crates/vk-gen-examples/IsZero-verify-proof-shplonk.json --assume-yes

{
  "Result": {
    "transaction_hash": "0x4f5e5709c0d41be10bc67a835aae1e1c8cb3893783bff59af5e486bbfaf434e2",
    "gas_used": 774,
    "gas_unit_price": 100,
    "sender": "b3046130693a6ba2712b171779d495ed297fb80bc0f72afae7626de519772a88",
    "sequence_number": 5,
    "success": true,
    "timestamp_us": 1706002504544312,
    "version": 2830235,
    "vm_status": "Executed successfully"
  }
}
```

### Tips
- once repeat the verification, please remove .aptos/config.yaml.
- please take care the folder to run command, for example, some command of "aptos run" need to run under root folder.

