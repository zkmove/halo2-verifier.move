use crate::public_inputs::PublicInputs;
use halo2::proofs::{verify_circuit, KZG};
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::plonk::{Error, ErrorFront};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::SerdeFormat;

pub mod circuit;
pub mod params;
pub mod public_inputs;

mod test;

/// Deserializes the circuit and reconstructs the vk, verifies the proof using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `params`: The serialized KZG parameters.
/// - `vk_bytes`: The serialized verification key.
/// - `circuit_bytes`: The serialized circuit environment.
/// - `public_inputs_bytes`: The serialized public inputs for the circuit.
/// - `proof`: The proof bytes to verify.
/// - `kzg`: An integer indicating the KZG variant to use (0 for GWC, 1 for SHPLONK).
/// - `k`: Optional new parameter k to downsize the KZG parameters if needed.
///
/// # Returns
/// `true` if the proof is valid, or `false` if verification fails.
pub fn deserialize_circuit_and_verify(
    params: &[u8],
    vk_bytes: &[u8],
    circuit_bytes: &[u8],
    public_inputs_bytes: &[u8],
    proof: &[u8],
    kzg: u8,
    k: Option<u32>,
) -> Result<(), Error> {
    let mut params =
        params::deserialize_kzg_params(params).expect("Failed to deserialize KZG parameters");
    if let Some(requested_k) = k {
        if requested_k > params.k() {
            return Err(ErrorFront::Other(
                "Cannot increase k beyond the original value".to_string(),
            )
            .into());
        }
        params.downsize(requested_k);
    }

    let cs = circuit::reconstruct_cs_from_circuit_bytes::<G1Affine>(circuit_bytes)
        .map_err(|e| ErrorFront::Other(format!("Constraint system reconstruction failed: {e}")))?;

    let vk = VerifyingKey::from_bytes(vk_bytes, SerdeFormat::RawBytes, cs)
        .map_err(|e| ErrorFront::Other(format!("Verification key deserialization failed: {e}")))?;

    let public_inputs = PublicInputs::<G1Affine>::from_bytes(public_inputs_bytes)
        .map_err(|e| ErrorFront::Other(format!("Public inputs deserialization failed: {e}")))?;

    let kzg_variant = KZG::from_u8(kzg)
        .ok_or_else(|| ErrorFront::Other("Invalid KZG variant (expected 0 or 1)".to_string()))?;

    verify_circuit(public_inputs.0, &params, &vk, proof, kzg_variant)
        .map_err(|e| ErrorFront::Other(format!("Verification failed: {e}")))?;
    Ok(())
}
