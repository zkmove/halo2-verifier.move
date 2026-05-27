module verifier_api::serialized_public_inputs;

use sui::hash;
use std::bcs;
use verifier_api::input_limits;

public struct PublicInputs has drop {
    columns: vector<vector<vector<u8>>>,
}

public struct SerializedPublicInputs has key, store {
    id: UID,
    version: u16,
    public_inputs_bytes: vector<u8>,
    public_inputs_digest: vector<u8>,
}

const EUnsupportedVersion: u64 = 2;
const VERSION: u16 = 1;

public fun artifact_version(): u16 { VERSION }

public fun from_bytes(bytes: vector<vector<vector<u8>>>): PublicInputs {
    PublicInputs { columns: bytes }
}

public fun to_bytes(public_inputs: &PublicInputs): vector<vector<vector<u8>>> {
    public_inputs.columns
}

public fun to_bcs_bytes(public_inputs: &PublicInputs): vector<u8> {
    bcs::to_bytes(&public_inputs.columns)
}

public fun new_serialized_public_inputs(
    public_inputs: PublicInputs,
    ctx: &mut TxContext,
): SerializedPublicInputs {
    new_serialized_public_inputs_from_bcs_bytes(to_bcs_bytes(&public_inputs), ctx)
}

public fun new_serialized_public_inputs_from_bcs_bytes(
    public_inputs_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedPublicInputs {
    input_limits::assert_public_inputs_size(&public_inputs_bytes);
    let public_inputs_digest = hash::blake2b256(&public_inputs_bytes);
    SerializedPublicInputs {
        id: object::new(ctx),
        version: VERSION,
        public_inputs_bytes,
        public_inputs_digest,
    }
}

entry fun publish_serialized_public_inputs(
    public_inputs: vector<vector<vector<u8>>>,
    ctx: &mut TxContext,
) {
    transfer::transfer(new_serialized_public_inputs(from_bytes(public_inputs), ctx), ctx.sender())
}

public fun assert_supported_version(public_inputs: &SerializedPublicInputs) {
    assert!(public_inputs.version == VERSION, EUnsupportedVersion)
}

public fun serialized_public_inputs_version(public_inputs: &SerializedPublicInputs): u16 {
    public_inputs.version
}

public fun public_inputs_bytes(public_inputs: &SerializedPublicInputs): vector<u8> {
    public_inputs.public_inputs_bytes
}

public fun public_inputs_digest(public_inputs: &SerializedPublicInputs): vector<u8> {
    public_inputs.public_inputs_digest
}

public fun destroy_serialized_public_inputs(public_inputs: SerializedPublicInputs) {
    let SerializedPublicInputs {
        id,
        version: _,
        public_inputs_bytes: _,
        public_inputs_digest: _,
    } = public_inputs;
    object::delete(id)
}
