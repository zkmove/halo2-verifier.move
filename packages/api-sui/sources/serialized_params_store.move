module verifier_api::serialized_params_store;

use sui::hash;
use verifier_api::input_limits;

const EUnsupportedVersion: u64 = 0;
const VERSION: u16 = 1;

public struct SerializedParams has key, store {
    id: UID,
    version: u16,
    params_bytes: vector<u8>,
    params_digest: vector<u8>,
}

public fun artifact_version(): u16 { VERSION }

public fun max_params_bytes(): u64 { input_limits::max_params_bytes() }

public fun new_serialized_params(
    params_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedParams {
    input_limits::assert_params_size(&params_bytes);
    let params_digest = hash::blake2b256(&params_bytes);
    SerializedParams {
        id: object::new(ctx),
        version: VERSION,
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

public fun version(params: &SerializedParams): u16 {
    params.version
}

public fun assert_supported_version(params: &SerializedParams) {
    assert!(params.version == VERSION, EUnsupportedVersion)
}

public fun params_bytes(params: &SerializedParams): vector<u8> {
    params.params_bytes
}

public fun params_digest(params: &SerializedParams): vector<u8> {
    params.params_digest
}

public fun destroy(params: SerializedParams) {
    let SerializedParams { id, version: _, params_bytes: _, params_digest: _ } = params;
    object::delete(id)
}
