module verifier_api::native_verifier;

use sui::halo2_kzg;

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

public fun kzg_gwc(): u8 { halo2_kzg::kzg_gwc() }

public fun kzg_shplonk(): u8 { halo2_kzg::kzg_shplonk() }

public fun native_abi_version(): u64 { halo2_kzg::abi_version() }

public fun verify_proof(
    params: vector<u8>,
    params_digest: vector<u8>,
    vk: vector<u8>,
    vk_digest: vector<u8>,
    circuit_info: vector<u8>,
    circuit_info_digest: vector<u8>,
    public_inputs: vector<u8>,
    proof: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
): bool {
    assert!(params.length() <= MAX_PARAMS_BYTES, EInputTooLarge);
    assert!(vk.length() <= MAX_VK_BYTES, EInputTooLarge);
    assert!(circuit_info.length() <= MAX_CIRCUIT_INFO_BYTES, EInputTooLarge);
    assert!(proof.length() <= MAX_PROOF_BYTES, EInputTooLarge);
    assert!(public_inputs.length() <= MAX_PUBLIC_INPUTS_BYTES, EInputTooLarge);

    halo2_kzg::verify_proof(
        params,
        params_digest,
        vk,
        vk_digest,
        circuit_info,
        circuit_info_digest,
        public_inputs,
        proof,
        kzg_variant,
        k_present,
        k,
    )
}
