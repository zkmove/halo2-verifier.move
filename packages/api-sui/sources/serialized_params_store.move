module verifier_api::serialized_params_store;

const EInputTooLarge: u64 = 1;

const MAX_PARAMS_BYTES: u64 = 240 * 1024;

public struct SerializedParams has key, store {
    id: UID,
    params_bytes: vector<u8>,
}

public fun max_params_bytes(): u64 { MAX_PARAMS_BYTES }

public fun new_serialized_params(
    params_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedParams {
    assert!(params_bytes.length() <= MAX_PARAMS_BYTES, EInputTooLarge);
    SerializedParams {
        id: object::new(ctx),
        params_bytes,
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

public fun destroy(params: SerializedParams) {
    let SerializedParams { id, params_bytes: _ } = params;
    object::delete(id)
}
