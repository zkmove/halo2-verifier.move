module verifier_api::input_limits;

const EInputTooLarge: u64 = 1;

const MAX_PARAMS_BYTES: u64 = 240 * 1024;
const MAX_VK_BYTES: u64 = 240 * 1024;
const MAX_CIRCUIT_INFO_BYTES: u64 = 240 * 1024;
const MAX_PROOF_BYTES: u64 = 96 * 1024;
const MAX_PUBLIC_INPUTS_BYTES: u64 = 16 * 1024;

public fun max_params_bytes(): u64 { MAX_PARAMS_BYTES }

public fun max_vk_bytes(): u64 { MAX_VK_BYTES }

public fun max_circuit_info_bytes(): u64 { MAX_CIRCUIT_INFO_BYTES }

public fun max_proof_bytes(): u64 { MAX_PROOF_BYTES }

public fun max_public_inputs_bytes(): u64 { MAX_PUBLIC_INPUTS_BYTES }

public fun assert_params_size(bytes: &vector<u8>) {
    assert!(bytes.length() <= MAX_PARAMS_BYTES, EInputTooLarge)
}

public fun assert_vk_size(bytes: &vector<u8>) {
    assert!(bytes.length() <= MAX_VK_BYTES, EInputTooLarge)
}

public fun assert_circuit_info_size(bytes: &vector<u8>) {
    assert!(bytes.length() <= MAX_CIRCUIT_INFO_BYTES, EInputTooLarge)
}

public fun assert_proof_size(bytes: &vector<u8>) {
    assert!(bytes.length() <= MAX_PROOF_BYTES, EInputTooLarge)
}

public fun assert_public_inputs_size(bytes: &vector<u8>) {
    assert!(bytes.length() <= MAX_PUBLIC_INPUTS_BYTES, EInputTooLarge)
}
