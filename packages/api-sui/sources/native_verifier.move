module verifier_api::native_verifier;

use halo2_common::serialized_public_inputs::{Self, PublicInputs};
use sui::hash;
use sui::halo2_kzg;
use verifier_api::serialized_params_store::{Self, SerializedParams};

const EInputTooLarge: u64 = 1;

const MAX_VK_BYTES: u64 = 240 * 1024;
const MAX_CIRCUIT_INFO_BYTES: u64 = 240 * 1024;
const MAX_PROOF_BYTES: u64 = 96 * 1024;
const MAX_PUBLIC_INPUTS_BYTES: u64 = 16 * 1024;

public struct SerializedVK has key, store {
    id: UID,
    vk_bytes: vector<u8>,
}

public struct SerializedCircuit has key, store {
    id: UID,
    circuit_bytes: vector<u8>,
}

public fun max_params_bytes(): u64 { serialized_params_store::max_params_bytes() }

public fun max_circuit_info_bytes(): u64 { MAX_CIRCUIT_INFO_BYTES }

public fun max_vk_bytes(): u64 { MAX_VK_BYTES }

public fun max_proof_bytes(): u64 { MAX_PROOF_BYTES }

public fun max_public_inputs_bytes(): u64 { MAX_PUBLIC_INPUTS_BYTES }

public fun kzg_gwc(): u8 { halo2_kzg::kzg_gwc() }

public fun kzg_shplonk(): u8 { halo2_kzg::kzg_shplonk() }

public fun native_abi_version(): u64 { halo2_kzg::abi_version() }

public fun new_serialized_vk(
    vk_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedVK {
    assert!(vk_bytes.length() <= MAX_VK_BYTES, EInputTooLarge);
    SerializedVK {
        id: object::new(ctx),
        vk_bytes,
    }
}

entry fun publish_serialized_vk(
    vk_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::transfer(new_serialized_vk(vk_bytes, ctx), ctx.sender())
}

public fun get_serialized_vk(vk: &SerializedVK): vector<u8> {
    vk.vk_bytes
}

public fun destroy_serialized_vk(vk: SerializedVK) {
    let SerializedVK { id, vk_bytes: _ } = vk;
    object::delete(id)
}

public fun new_serialized_circuit(
    circuit_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedCircuit {
    assert!(circuit_bytes.length() <= MAX_CIRCUIT_INFO_BYTES, EInputTooLarge);
    SerializedCircuit {
        id: object::new(ctx),
        circuit_bytes,
    }
}

entry fun publish_serialized_circuit(
    circuit_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::transfer(new_serialized_circuit(circuit_bytes, ctx), ctx.sender())
}

public fun get_serialized_circuit(circuit: &SerializedCircuit): vector<u8> {
    circuit.circuit_bytes
}

public fun destroy_serialized_circuit(circuit: SerializedCircuit) {
    let SerializedCircuit { id, circuit_bytes: _ } = circuit;
    object::delete(id)
}

public fun verify_proof_bytes(
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
    assert!(params.length() <= max_params_bytes(), EInputTooLarge);
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

public fun verify_proof(
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    public_inputs: PublicInputs,
    proof: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
): bool {
    let params_bytes = serialized_params_store::params_bytes(params);
    let vk_bytes = get_serialized_vk(vk);
    let circuit_info = get_serialized_circuit(circuit);
    let public_inputs_bytes = serialized_public_inputs::to_bcs_bytes(&public_inputs);

    verify_proof_bytes(
        params_bytes,
        hash::blake2b256(&params_bytes),
        vk_bytes,
        hash::blake2b256(&vk_bytes),
        circuit_info,
        hash::blake2b256(&circuit_info),
        public_inputs_bytes,
        proof,
        kzg_variant,
        k_present,
        k,
    )
}
