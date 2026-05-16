module verifier_api::serialized_params_store;

use sui::hash;
use verifier_api::input_limits;

public struct SerializedParams has key, store {
    id: UID,
    params_bytes: vector<u8>,
    params_digest: vector<u8>,
}

public fun max_params_bytes(): u64 { input_limits::max_params_bytes() }

public fun new_serialized_params(
    params_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedParams {
    input_limits::assert_params_size(&params_bytes);
    let params_digest = hash::blake2b256(&params_bytes);
    SerializedParams {
        id: object::new(ctx),
        params_bytes,
        params_digest,
    }
}

entry fun publish_serialized_params(
    params_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::transfer(
        new_serialized_params(params_bytes, ctx),
        ctx.sender(),
    )
}

public fun params_bytes(params: &SerializedParams): vector<u8> {
    params.params_bytes
}

public fun params_digest(params: &SerializedParams): vector<u8> {
    params.params_digest
}

public fun destroy(params: SerializedParams) {
    let SerializedParams { id, params_bytes: _, params_digest: _ } = params;
    object::delete(id)
}
