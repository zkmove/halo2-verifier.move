module verifier_api::native_verifier;

use sui::hash;
use sui::halo2_kzg;
use verifier_api::input_limits;
use verifier_api::serialized_public_inputs::{Self, PublicInputs};
use verifier_api::serialized_params_store::{Self, SerializedParams};

const EVerifyProof: u64 = 2;
const EUnsupportedVersion: u64 = 3;
const VERSION: u16 = 1;

/// A verification key + its matching circuit info, stored together.
///
/// The Aptos counterpart publishes `SerializedVK` and `SerializedCircuit`
/// as two separate resources at the same owner address and the verify
/// entry reads both off that address. Sui's object model doesn't allow
/// "look up an object by owner inside Move", so we mirror that coupling
/// by packing both byte blobs into a single object - clients only need to
/// reference one object id when calling `verify`.
public struct SerializedVK has key, store {
    id: UID,
    version: u16,
    vk_bytes: vector<u8>,
    vk_digest: vector<u8>,
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

/// Construct a `SerializedVK` from raw vk and circuit bytes.
public fun new_serialized_vk(
    vk_bytes: vector<u8>,
    circuit_bytes: vector<u8>,
    ctx: &mut TxContext,
): SerializedVK {
    input_limits::assert_vk_size(&vk_bytes);
    input_limits::assert_circuit_info_size(&circuit_bytes);
    let vk_digest = hash::blake2b256(&vk_bytes);
    let circuit_digest = hash::blake2b256(&circuit_bytes);
    SerializedVK {
        id: object::new(ctx),
        version: VERSION,
        vk_bytes,
        vk_digest,
        circuit_bytes,
        circuit_digest,
    }
}

/// Entry-friendly wrapper around `new_serialized_vk` that transfers the
/// resulting object to the transaction sender.
entry fun publish_serialized_vk(
    vk_bytes: vector<u8>,
    circuit_bytes: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::transfer(new_serialized_vk(vk_bytes, circuit_bytes, ctx), ctx.sender())
}

public fun serialized_vk_version(vk: &SerializedVK): u16 {
    vk.version
}

/// Return the vk byte payload (the Halo2 verification key blob).
public fun get_serialized_vk(vk: &SerializedVK): vector<u8> {
    vk.vk_bytes
}

public fun get_serialized_vk_digest(vk: &SerializedVK): vector<u8> {
    vk.vk_digest
}

/// Return the circuit-info byte payload bound to this verification key.
/// Mirrors `verifier_api::native_verifier::get_serialized_circuit(addr)` on Aptos.
public fun get_serialized_circuit(vk: &SerializedVK): vector<u8> {
    vk.circuit_bytes
}

public fun get_serialized_circuit_digest(vk: &SerializedVK): vector<u8> {
    vk.circuit_digest
}

public fun destroy_serialized_vk(vk: SerializedVK) {
    let SerializedVK {
        id,
        version: _,
        vk_bytes: _,
        vk_digest: _,
        circuit_bytes: _,
        circuit_digest: _,
    } = vk;
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

/// Verify a proof against `params` + `vk` (which carries the circuit info).
///
/// This is the in-Move callable; takes a typed `PublicInputs` and returns
/// `bool` instead of aborting. Use this from another Move module that wants
/// to make a decision on the result.
public fun verify_proof(
    params: &SerializedParams,
    vk: &SerializedVK,
    public_inputs: PublicInputs,
    proof: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
): bool {
    serialized_params_store::assert_supported_version(params);
    assert_supported_vk_version(vk);

    let public_inputs_bytes = serialized_public_inputs::to_bcs_bytes(&public_inputs);
    input_limits::assert_public_inputs_size(&public_inputs_bytes);

    verify_proof_bcs(params, vk, public_inputs_bytes, proof, kzg_variant, k_present, k)
}

/// Verify a proof where public inputs are already BCS-encoded. This is used by
/// chunked proof upload flows that cannot pass `proof` as one Sui pure argument.
public(package) fun verify_proof_bcs(
    params: &SerializedParams,
    vk: &SerializedVK,
    public_inputs: vector<u8>,
    proof: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
): bool {
    serialized_params_store::assert_supported_version(params);
    assert_supported_vk_version(vk);

    input_limits::assert_public_inputs_size(&public_inputs);
    input_limits::assert_proof_size(&proof);

    verify_proof_bytes_inner(
        serialized_params_store::params_bytes(params),
        serialized_params_store::params_digest(params),
        vk.vk_bytes,
        vk.vk_digest,
        vk.circuit_bytes,
        vk.circuit_digest,
        public_inputs,
        proof,
        kzg_variant,
        k_present,
        k,
    )
}

/// Verify entry mirroring `verifier_api::native_verifier::verify` on Aptos:
/// only two object references (`params`, `vk`) and a single BCS-encoded
/// `public_inputs: vector<u8>` payload. Aborts with `EVerifyProof` on failure.
///
/// Clients build `public_inputs` exactly like Aptos:
///   `bcs::to_bytes(&Vec<Vec<Vec<u8>>>)` over the column-major scalar layout.
/// The Sui Move helper `serialized_public_inputs::to_bcs_bytes(&pi)` produces
/// the same bytes.
entry fun verify(
    params: &SerializedParams,
    vk: &SerializedVK,
    public_inputs: vector<u8>,
    proof: vector<u8>,
    kzg_variant: u8,
    k_present: bool,
    k: u32,
) {
    assert!(
        verify_proof_bcs(params, vk, public_inputs, proof, kzg_variant, k_present, k),
        EVerifyProof,
    )
}

/// Test-only twin of `verify_proof` that always returns `true`. Mirrors
/// `verifier_api::native_verifier::mock_verify_proof` on Aptos. Use this in
/// downstream example tests that exercise non-ZKP paths without a real
/// proof fixture.
#[test_only]
public fun mock_verify_proof(
    _params: &SerializedParams,
    _vk: &SerializedVK,
    _public_inputs: PublicInputs,
    _proof: vector<u8>,
    _kzg_variant: u8,
    _k_present: bool,
    _k: u32,
): bool {
    true
}
