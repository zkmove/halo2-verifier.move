module verifier_api::serialized_public_inputs;

use std::bcs;

public struct PublicInputs has drop {
    columns: vector<vector<vector<u8>>>,
}

public fun from_bytes(bytes: vector<vector<vector<u8>>>): PublicInputs {
    PublicInputs { columns: bytes }
}

public fun to_bytes(public_inputs: &PublicInputs): vector<vector<vector<u8>>> {
    public_inputs.columns
}

public fun to_bcs_bytes(public_inputs: &PublicInputs): vector<u8> {
    bcs::to_bytes(&public_inputs.columns)
}
