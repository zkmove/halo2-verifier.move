module verifier_api::serialized_params_store;

use sui::event;
use sui::hash;
use verifier_api::input_limits;

const EUnsupportedVersion: u64 = 0;
const EEmptyParams: u64 = 1;
const EParamsNotFound: u64 = 2;
const EUnauthorized: u64 = 3;
const VERSION: u16 = 1;

/// Serialized KZG params artifact. Equivalent to the Aptos
/// `SerializedParams` resource: one logical "slot per publisher", but
/// addressed by Sui object id rather than by owner address.
///
/// Lifecycle (two supported flows):
/// 1. Shared-store flow (mirrors Aptos `move_to`-per-account):
///    - `create_serialized_params_store` creates an empty shared object
///      and records the sender as `publisher`.
///    - `publish_serialized_params` writes / overwrites `params_bytes`
///      and is guarded by `sender == publisher`.
/// 2. Owned / frozen flow (used by the chunked `artifact_builder` path):
///    - `new_serialized_params` builds a fully-populated object that
///      `artifact_builder` immediately transfers to sender or freezes.
///      `publisher` is set to the creator and there is no separate
///      "publish" step because the object is not shared.
public struct SerializedParams has key, store {
    id: UID,
    publisher: address,
    version: u16,
    params_bytes: vector<u8>,
    params_digest: vector<u8>,
}

public struct SerializedParamsPublished has copy, drop {
    publisher: address,
    version: u16,
    digest: vector<u8>,
    size: u64,
}

public fun artifact_version(): u16 { VERSION }

public fun max_params_bytes(): u64 { input_limits::max_params_bytes() }

/// Create an empty `SerializedParams` slot owned (logically) by the
/// transaction sender. The slot must later be populated via
/// `publish_serialized_params`.
public fun new_empty(ctx: &mut TxContext): SerializedParams {
    SerializedParams {
        id: object::new(ctx),
        publisher: ctx.sender(),
        version: VERSION,
        params_bytes: vector[],
        params_digest: vector[],
    }
}

/// Shared-store flow: create an empty slot and share it. Pair with
/// `publish_serialized_params` from the same sender to populate it.
entry fun create_serialized_params_store(ctx: &mut TxContext) {
    transfer::share_object(new_empty(ctx))
}

/// Build a fully-populated `SerializedParams` in one shot. Used by the
/// chunked `artifact_builder` finalize entries (transfer-to-sender or
/// freeze) and by test fixtures. `publisher` is recorded as the sender
/// and a `SerializedParamsPublished` event is emitted.
public fun new_serialized_params(
    params_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedParams {
    assert!(params_bytes.length() > 0, EEmptyParams);
    input_limits::assert_params_size(&params_bytes);
    let publisher = ctx.sender();
    let params_digest = hash::blake2b256(&params_bytes);
    let size = params_bytes.length();
    let params = SerializedParams {
        id: object::new(ctx),
        publisher,
        version: VERSION,
        params_bytes,
        params_digest,
    };
    event::emit(SerializedParamsPublished {
        publisher,
        version: VERSION,
        digest: params_digest,
        size,
    });
    params
}

/// Shared-store flow: overwrite `params_bytes` on a previously-shared
/// slot. Only the original creator (`store.publisher`) can call this.
public fun publish_serialized_params(
    store: &mut SerializedParams,
    params_bytes: vector<u8>,
    ctx: &TxContext,
) {
    assert!(store.publisher == ctx.sender(), EUnauthorized);
    assert!(params_bytes.length() > 0, EEmptyParams);
    input_limits::assert_params_size(&params_bytes);

    let digest = hash::blake2b256(&params_bytes);
    let size = params_bytes.length();
    store.version = VERSION;
    store.params_digest = digest;
    store.params_bytes = params_bytes;

    event::emit(SerializedParamsPublished {
        publisher: store.publisher,
        version: VERSION,
        digest,
        size,
    });
}

public fun publisher(params: &SerializedParams): address { params.publisher }

public fun version(params: &SerializedParams): u16 { params.version }

public fun assert_supported_version(params: &SerializedParams) {
    assert!(params.version == VERSION, EUnsupportedVersion)
}

public fun params_bytes(params: &SerializedParams): vector<u8> {
    assert!(params.params_bytes.length() > 0, EParamsNotFound);
    params.params_bytes
}

public fun params_digest(params: &SerializedParams): vector<u8> {
    assert!(params.params_bytes.length() > 0, EParamsNotFound);
    params.params_digest
}

public fun destroy(params: SerializedParams) {
    let SerializedParams { id, publisher: _, version: _, params_bytes: _, params_digest: _ } = params;
    object::delete(id)
}
