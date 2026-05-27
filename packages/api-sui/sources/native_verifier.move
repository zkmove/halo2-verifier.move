module verifier_api::native_verifier;

use sui::hash;
use sui::halo2_kzg;
use verifier_api::input_limits;
use verifier_api::serialized_public_inputs::{Self, PublicInputs};
use verifier_api::serialized_params_store::{Self, SerializedParams};

const EVerifyProof: u64 = 2;
const EUnsupportedVersion: u64 = 3;
const VERSION: u16 = 1;

public struct SerializedVK has key, store {
    id: UID,
    version: u16,
    vk_bytes: vector<u8>,
    vk_digest: vector<u8>,
}

public struct SerializedCircuit has key, store {
    id: UID,
    version: u16,
    circuit_bytes: vector<u8>,
    circuit_digest: vector<u8>,
}

public fun artifact_version(): u16 { VERSION }

public fun max_params_bytes(): u64 { serialized_params_store::max_params_bytes() }

public fun max_circuit_info_bytes(): u64 { input_limits::max_circuit_info_bytes() }

public fun max_vk_bytes(): u64 { input_limits::max_vk_bytes() }

public fun max_proof_bytes(): u64 { input_limits::max_proof_bytes() }

public fun max_public_inputs_bytes(): u64 { input_limits::max_public_inputs_bytes() }

public fun kzg_gwc(): u8 { halo2_kzg::kzg_gwc() }

public fun kzg_shplonk(): u8 { halo2_kzg::kzg_shplonk() }

public fun native_abi_version(): u64 { halo2_kzg::abi_version() }

public fun new_serialized_vk(
    vk_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedVK {
    input_limits::assert_vk_size(&vk_bytes);
    let vk_digest = hash::blake2b256(&vk_bytes);
    SerializedVK {
        id: object::new(ctx),
        version: VERSION,
        vk_bytes,
        vk_digest,
    }
}

entry fun publish_serialized_vk(
    vk_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::transfer(new_serialized_vk(vk_bytes, ctx), ctx.sender())
}

public fun serialized_vk_version(vk: &SerializedVK): u16 {
    vk.version
}

public fun get_serialized_vk(vk: &SerializedVK): vector<u8> {
    vk.vk_bytes
}

public fun get_serialized_vk_digest(vk: &SerializedVK): vector<u8> {
    vk.vk_digest
}

public fun destroy_serialized_vk(vk: SerializedVK) {
    let SerializedVK { id, version: _, vk_bytes: _, vk_digest: _ } = vk;
    object::delete(id)
}

public fun new_serialized_circuit(
    circuit_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedCircuit {
    input_limits::assert_circuit_info_size(&circuit_bytes);
    let circuit_digest = hash::blake2b256(&circuit_bytes);
    SerializedCircuit {
        id: object::new(ctx),
        version: VERSION,
        circuit_bytes,
        circuit_digest,
    }
}

entry fun publish_serialized_circuit(
    circuit_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::transfer(new_serialized_circuit(circuit_bytes, ctx), ctx.sender())
}

public fun serialized_circuit_version(circuit: &SerializedCircuit): u16 {
    circuit.version
}

public fun get_serialized_circuit(circuit: &SerializedCircuit): vector<u8> {
    circuit.circuit_bytes
}

public fun get_serialized_circuit_digest(circuit: &SerializedCircuit): vector<u8> {
    circuit.circuit_digest
}

public fun destroy_serialized_circuit(circuit: SerializedCircuit) {
    let SerializedCircuit { id, version: _, circuit_bytes: _, circuit_digest: _ } = circuit;
    object::delete(id)
}

public(package) fun verify_proof_bytes(
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
    input_limits::assert_params_size(&params);
    input_limits::assert_vk_size(&vk);
    input_limits::assert_circuit_info_size(&circuit_info);
    input_limits::assert_proof_size(&proof);
    input_limits::assert_public_inputs_size(&public_inputs);

    verify_proof_bytes_inner(
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

fun verify_proof_bytes_inner(
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

fun assert_supported_vk_version(vk: &SerializedVK) {
    assert!(vk.version == VERSION, EUnsupportedVersion)
}

fun assert_supported_circuit_version(circuit: &SerializedCircuit) {
    assert!(circuit.version == VERSION, EUnsupportedVersion)
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
    serialized_params_store::assert_supported_version(params);
    assert_supported_vk_version(vk);
    assert_supported_circuit_version(circuit);

    let params_bytes = serialized_params_store::params_bytes(params);
    let params_digest = serialized_params_store::params_digest(params);
    let vk_bytes = get_serialized_vk(vk);
    let vk_digest = get_serialized_vk_digest(vk);
    let circuit_info = get_serialized_circuit(circuit);
    let circuit_digest = get_serialized_circuit_digest(circuit);
    let public_inputs_bytes = serialized_public_inputs::to_bcs_bytes(&public_inputs);

    input_limits::assert_public_inputs_size(&public_inputs_bytes);

    verify_proof_bytes_inner(
        params_bytes,
        params_digest,
        vk_bytes,
        vk_digest,
        circuit_info,
        circuit_digest,
        public_inputs_bytes,
        proof,
        kzg_variant,
        k_present,
        k,
    )
}

entry fun verify(
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    public_inputs: vector<vector<vector<u8>>>,
    proof: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
) {
    let public_inputs = serialized_public_inputs::from_bytes(public_inputs);
    assert!(
        verify_proof(
            params,
            vk,
            circuit,
            public_inputs,
            proof,
            kzg_variant,
            k_present,
            k,
        ),
        EVerifyProof,
    )
}
