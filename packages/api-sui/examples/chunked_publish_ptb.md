# Chunked verifier artifact PTB flow

This package exposes Sui object builders so large verifier artifacts can be
uploaded across multiple transactions, then finalized into reusable verifier
objects.

The on-chain flow is:

```text
publish_*_builder
  -> append_chunk(builder, chunk)     # repeat across one or more PTBs
  -> finalize_*_to_sender(builder, expected_digest)
  -> dapp calls verifier_api::native_verifier::verify_proof(...)
```

## Artifact objects

The finalized objects are:

```text
verifier_api::serialized_params_store::SerializedParams
verifier_api::native_verifier::SerializedVK
```

Use a chunk size no larger than:

```text
verifier_api::input_limits::max_chunk_bytes() == 15 KiB
```

The value is intentionally below Sui's 16 KiB `max_pure_argument_size` so the
BCS `vector<u8>` length prefix has headroom.

The finalize calls require the expected `blake2b256` digest of the full byte
array. This catches missing, reordered, or corrupted chunks before the artifact
object is created.

Client-side digest calculation must use Blake2b with 256-bit output, no key, no
salt, and no personalization.

The builder emits these events for localnet scripts and indexers:

```text
verifier_api::artifact_builder::BuilderCreated
verifier_api::artifact_builder::ChunkAppended
verifier_api::artifact_builder::ArtifactFinalized
```

`ArtifactFinalized` includes the finalized artifact object ID.

Builder IDs can also be read from transaction effects. In TypeScript SDK terms:

```ts
const created = result.effects?.created ?? [];
const builderId = created.find((o) => o.owner?.AddressOwner === sender)
  ?.reference.objectId;
```

## PTB shape

Below is the intended PTB sequence. Replace `$API_PACKAGE`, `$DAPP_PACKAGE`,
object IDs, and byte arrays with values from your deployment.

### 1. Create builders

```text
move_call $API_PACKAGE::artifact_builder::publish_params_builder()
move_call $API_PACKAGE::artifact_builder::publish_vk_builder()
move_call $API_PACKAGE::artifact_builder::publish_circuit_info_builder()
```

Each call transfers an owned `ArtifactBuilder` object to the sender.

### 2. Append chunks

Run one or more PTBs per builder:

```text
move_call $API_PACKAGE::artifact_builder::append_chunk(
  &mut $PARAMS_BUILDER,
  $PARAMS_CHUNK_N,
)

move_call $API_PACKAGE::artifact_builder::append_chunk(
  &mut $VK_BUILDER,
  $VK_CHUNK_N,
)

move_call $API_PACKAGE::artifact_builder::append_chunk(
  &mut $CIRCUIT_INFO_BUILDER,
  $CIRCUIT_INFO_CHUNK_N,
)
```

Every chunk must be `<= 15 KiB`, and each builder enforces the total artifact
limit for its kind.

### 3. Finalize artifacts

```text
move_call $API_PACKAGE::artifact_builder::finalize_params_to_sender(
  $PARAMS_BUILDER,
  $PARAMS_DIGEST,
)

move_call $API_PACKAGE::artifact_builder::finalize_vk_to_sender(
  $VK_BUILDER,
  $CIRCUIT_INFO_BUILDER,
  $VK_DIGEST,
  $CIRCUIT_INFO_DIGEST,
)
```

The sender receives reusable verifier artifact objects:

```text
$PARAMS_OBJECT
$VK_OBJECT
```

For artifacts that should be reused by multiple dapps/users, prefer finalizing
directly to immutable objects:

```text
move_call $API_PACKAGE::artifact_builder::finalize_params_and_freeze(...)
move_call $API_PACKAGE::artifact_builder::finalize_vk_and_freeze(...)
```

Otherwise, use the `*_to_sender` variants and freeze the objects in a later PTB
with `transfer::public_freeze_object`.

### 4. Call a dapp verifier path

For a dapp shaped like the Sui examples under `zkmove/examples/*/on-chain-sui`,
first create the dapp-owned objects:

```text
move_call $DAPP_PACKAGE::token::publish_mint_cap()
move_call $DAPP_PACKAGE::token::register_to_sender()
```

or:

```text
move_call $DAPP_PACKAGE::game::new_game_to_sender()
```

Then pass the finalized verifier objects into the dapp entry function:

```text
move_call $DAPP_PACKAGE::token::mint_from_bytes(
  &$MINT_CAP,
  &mut $STORE,
  &$PARAMS_OBJECT,
  &$VK_OBJECT,
  $ENCRYPTED_AMOUNT,
  $PUBLIC_INPUTS,
  $PROOF,
)
```

or:

```text
move_call $DAPP_PACKAGE::game::create_planet_from_bytes(
  &mut $GAME,
  $PLAYER_ADDRESS,
  &$PARAMS_OBJECT,
  &$VK_OBJECT,
  $COORD_HASH,
  $PUBLIC_INPUTS,
  $PROOF,
)
```

The dark-forest example also exposes:

```text
move_call $DAPP_PACKAGE::game::dispatch_fleet_entry(...)
move_call $DAPP_PACKAGE::game::process_arrival_from_bytes(...)
```

Those dapp calls route to:

```text
verifier_api::native_verifier::verify_proof
  -> sui::halo2_kzg::verify_proof
```

## TypeScript SDK sketch

```ts
const tx = new Transaction();

tx.moveCall({
  target: `${apiPackage}::artifact_builder::append_chunk`,
  arguments: [
    tx.object(paramsBuilderId),
    tx.pure.vector("u8", Array.from(paramsChunk)),
  ],
});

tx.moveCall({
  target: `${apiPackage}::artifact_builder::finalize_params_to_sender`,
  arguments: [
    tx.object(paramsBuilderId),
    tx.pure.vector("u8", Array.from(paramsDigest)),
  ],
});
```

Create separate PTBs for upload chunks when the full artifact would exceed the
transaction input budget.
