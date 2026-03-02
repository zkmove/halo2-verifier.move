use crate::circuit::{
    circuit_info::CircuitInfo, generate_circuit_info, reconstruct_cs_from_circuit_info,
};
use crate::public_inputs::PublicInputs;
use group::ff::Field;
use halo2::proofs::{prove_circuit, verify_circuit};
use halo2_backend::arithmetic::CurveAffine;
use halo2_backend::plonk::ConstraintSystemBack as ConstraintSystem;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit, Error, ErrorFront, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::SerdeFormat;

use crate::params::serialize_kzg_params;
pub use halo2::proofs::KZG;

pub mod circuit;
pub mod params;
pub mod public_inputs;

#[cfg(test)]
mod tests;

use hex::encode;

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
        .map_err(|e| {
            println!("Verification failed: {e}"); //todo: remove this
            ErrorFront::Other(format!("Verification failed: {e}"))
        })?;
    Ok(())
}

pub struct VerifierTestData {
    pub serialized_params: Vec<u8>,
    pub vk_bytes: Vec<u8>,
    pub circuit_info_bytes: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
}

///  Only for testing purposes to verify the correctness of vk reconstruction from circuit info.
pub fn test_verifier<C>(
    circuit: C,
    instances: Vec<Vec<Fr>>,
    params: &ParamsKZG<Bn256>,
    kzg: KZG,
) -> Result<VerifierTestData, Error>
where
    C: Circuit<Fr> + Clone,
{
    let vk = keygen_vk(params, &circuit)
        .map_err(|e| ErrorFront::Other(format!("Keygen vk failed: {e}")))?;
    let pk = keygen_pk(params, vk.clone(), &circuit)
        .map_err(|e| ErrorFront::Other(format!("Keygen pk failed: {e}")))?;
    let proof = prove_circuit(circuit.clone(), instances.clone(), params, &pk, kzg)
        .map_err(|e| ErrorFront::Other(format!("Proving failed: {e}")))?;
    let public_inputs_bytes = PublicInputs::<G1Affine>(instances.clone()).to_bytes();

    verify_circuit(instances, &params.verifier_params(), &vk, &proof, kzg)
        .map_err(|e| ErrorFront::Other(format!("Verification failed: {e}")))?;

    // check circuit_info serialization and deserialization
    let circuit_info = generate_circuit_info(params, &circuit)
        .map_err(|e| ErrorFront::Other(format!("Generate circuit info failed: {e}")))?;
    let circuit_info_bytes = circuit_info
        .to_bytes()
        .map_err(|e| ErrorFront::Other(format!("Serialize circuit info failed: {e}")))?;
    let deserialized_circuit_info = CircuitInfo::from_bytes(&circuit_info_bytes)
        .map_err(|e| ErrorFront::Other(format!("Deserialize circuit info failed: {e}")))?;
    assert_eq!(circuit_info, deserialized_circuit_info);

    // check cs reconstruction
    let cs = vk.cs().clone();
    let reconstructed_cs = reconstruct_cs_from_circuit_info(&deserialized_circuit_info)?;
    if !cs_eq::<G1Affine>(&cs, &reconstructed_cs) {
        return Err(ErrorFront::Other(
            "Reconstructed constraint system is not equivalent to the original".to_string(),
        )
        .into());
    }

    // check vk reconstruction
    let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
    let reconstructed_vk: VerifyingKey<G1Affine> =
        VerifyingKey::from_bytes(vk_bytes.as_slice(), SerdeFormat::RawBytes, reconstructed_cs)
            .map_err(|e| ErrorFront::Other(format!("Reconstruct vk failed: {e}")))?;
    let vk_pinned = format!("{:?}", vk.pinned());
    let reconstructed_vk_pinned = format!("{:?}", reconstructed_vk.pinned());
    assert_eq!(vk_pinned, reconstructed_vk_pinned);

    // check public inputs serialization and deserialization
    let public_inputs = PublicInputs::<G1Affine>::from_bytes(&public_inputs_bytes)
        .map_err(|e| ErrorFront::Other(format!("Deserialize public inputs failed: {e}")))?
        .0;
    let roundtrip_public_inputs_bytes = PublicInputs::<G1Affine>(public_inputs.clone()).to_bytes();
    assert_eq!(public_inputs_bytes, roundtrip_public_inputs_bytes);

    verify_circuit(
        public_inputs,
        &params.verifier_params(),
        &reconstructed_vk,
        &proof,
        kzg,
    )
    .map_err(|e| ErrorFront::Other(format!("Verify with reconstructed vk failed: {e}")))?;

    let serialized_params = serialize_kzg_params(&params.verifier_params())
        .expect("Failed to serialize KZG parameters");

    deserialize_circuit_and_verify(
        &serialized_params,
        vk_bytes.as_slice(),
        &circuit_info_bytes,
        &public_inputs_bytes,
        proof.as_slice(),
        kzg.to_u8(),
        None,
    )?;

    Ok(VerifierTestData {
        serialized_params,
        vk_bytes,
        circuit_info_bytes,
        proof,
        public_inputs_bytes,
    })
}

// Helper function to check if two constraint systems are equivalent (for testing purposes).
fn cs_eq<C: CurveAffine>(a: &ConstraintSystem<C::Scalar>, b: &ConstraintSystem<C::Scalar>) -> bool
where
    C::Scalar: Field + std::fmt::Debug,
{
    if a.num_fixed_columns != b.num_fixed_columns {
        return false;
    }
    if a.num_advice_columns != b.num_advice_columns {
        return false;
    }
    if a.num_instance_columns != b.num_instance_columns {
        return false;
    }
    if a.num_challenges != b.num_challenges {
        return false;
    }
    if a.unblinded_advice_columns != b.unblinded_advice_columns {
        return false;
    }
    if a.advice_column_phase != b.advice_column_phase {
        return false;
    }
    if a.challenge_phase != b.challenge_phase {
        return false;
    }
    if a.advice_queries != b.advice_queries {
        return false;
    }
    if a.fixed_queries != b.fixed_queries {
        return false;
    }
    if a.instance_queries != b.instance_queries {
        return false;
    }
    if a.num_advice_queries != b.num_advice_queries {
        return false;
    }
    if a.permutation.columns != b.permutation.columns {
        return false;
    }
    if a.lookups.len() != b.lookups.len() {
        return false;
    }
    if a.shuffles.len() != b.shuffles.len() {
        return false;
    }
    if a.gates.len() != b.gates.len() {
        return false;
    }
    if a.minimum_degree != b.minimum_degree {
        return false;
    }

    let mut gates_match = true;
    for (i, (a_gate, b_gate)) in a.gates.iter().zip(b.gates.iter()).enumerate() {
        if a_gate.poly != b_gate.poly {
            println!(
                "gate[{i}] poly mismatch: a={:?} b={:?}",
                a_gate.poly, b_gate.poly
            );
            gates_match = false;
        }
    }
    if !gates_match {
        return false;
    }

    let mut lookups_match = true;
    for (i, (a_lookup, b_lookup)) in a.lookups.iter().zip(b.lookups.iter()).enumerate() {
        if a_lookup.input_expressions != b_lookup.input_expressions {
            println!(
                "lookup[{i}] input mismatch: a={:?} b={:?}",
                a_lookup.input_expressions, b_lookup.input_expressions
            );
            lookups_match = false;
        }
        if a_lookup.table_expressions != b_lookup.table_expressions {
            println!(
                "lookup[{i}] table mismatch: a={:?} b={:?}",
                a_lookup.table_expressions, b_lookup.table_expressions
            );
            lookups_match = false;
        }
    }
    if !lookups_match {
        return false;
    }

    let mut shuffles_match = true;
    for (i, (a_shuffle, b_shuffle)) in a.shuffles.iter().zip(b.shuffles.iter()).enumerate() {
        if a_shuffle.input_expressions != b_shuffle.input_expressions {
            println!(
                "shuffle[{i}] input mismatch: a={:?} b={:?}",
                a_shuffle.input_expressions, b_shuffle.input_expressions
            );
            shuffles_match = false;
        }
        if a_shuffle.shuffle_expressions != b_shuffle.shuffle_expressions {
            println!(
                "shuffle[{i}] shuffle mismatch: a={:?} b={:?}",
                a_shuffle.shuffle_expressions, b_shuffle.shuffle_expressions
            );
            shuffles_match = false;
        }
    }
    if !shuffles_match {
        return false;
    }

    true
}
