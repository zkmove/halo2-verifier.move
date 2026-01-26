// rust
use halo2::proofs::{prove_circuit, verify_circuit, KZG};
use halo2_backend::plonk::VerifyingKey;
use halo2_backend::poly::commitment::Params;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Error};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use rand::rngs::mock::StepRng;

use crate::examples::{
    circuit_layout, serialization, shuffle, shuffle_api, simple_example, two_chip, vector_mul,
};
use shape_generator::params::{load_default_kzg_params, serialize_kzg_params};
use shape_generator::public_inputs::PublicInputs;
use shape_generator::{
    circuit_info::CircuitInfo, deserialize_and_verify, generate_circuit_info,
    reconstruct_cs_from_circuit_info,
};

fn create_test_params(k: u32) -> ParamsKZG<Bn256> {
    let rng = StepRng::new(0, 1);
    ParamsKZG::<Bn256>::setup(k, rng)
}

macro_rules! check_circuit_info {
    ($name:expr, $circuit_expr:expr, $params:expr) => {{
        let circuit = $circuit_expr;
        let circuit_info =
            generate_circuit_info($params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info =
            CircuitInfo::deserialize(serialized_circuit_info).expect("Failed to deserialize");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "{}: Deserialized circuit info does not match original",
            $name
        );
        println!("✓ {} passed", $name);
    }};
}

macro_rules! run_reconstruction {
    ($name:expr, $get_circuit:expr, $params:expr, $serialized_params:expr) => {{
        let (circuit, instances) = $get_circuit;
        let vk = keygen_vk($params, &circuit).unwrap();
        let pk = keygen_pk($params, vk.clone(), &circuit).unwrap();
        let proof = prove_circuit(circuit.clone(), instances.clone(), $params, &pk, KZG::GWC)
            .expect("proving should not fail");
        let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);

        let circuit_info =
            generate_circuit_info($params, &circuit).expect("Failed to generate circuit info");
        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info.clone())
            .expect("Failed to deserialize");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "{}: Deserialized circuit info does not match original",
            $name
        );

        let reconstructed_circuit = reconstruct_cs_from_circuit_info(&deserialized_circuit_info)?;
        let reconstructed_vk = VerifyingKey::from_bytes(
            vk_bytes.as_slice(),
            SerdeFormat::RawBytes,
            reconstructed_circuit,
        )
        .expect("Failed to reconstruct vk from bytes");

        let serialized_public_inputs = PublicInputs::<G1Affine>(instances).to_bytes();
        let public_inputs = PublicInputs::<G1Affine>::from_bytes(&serialized_public_inputs)
            .expect("Failed to deserialize public inputs")
            .0;

        verify_circuit(public_inputs, $params, &reconstructed_vk, &proof, KZG::GWC)
            .expect("verify proof should not fail");

        let kzg = KZG::GWC.to_u8();
        deserialize_and_verify(
            $serialized_params.as_slice(),
            vk_bytes.as_slice(),
            serialized_circuit_info,
            serialized_public_inputs,
            proof.as_slice(),
            kzg,
            None,
        )?;
        println!("✓ {} passed", $name);
    }};
}

#[test]
fn test_circuit_serialization() {
    let params = create_test_params(8);

    check_circuit_info!(
        "circuit_layout",
        circuit_layout::get_example_circuit::<Fr>(),
        &params
    );
    check_circuit_info!(
        "serialization",
        serialization::get_example_circuit().0,
        &params
    );
    check_circuit_info!("shuffle", shuffle::get_example_circuit(), &params);
    check_circuit_info!("shuffle_api", shuffle_api::get_example_circuit(), &params);
    check_circuit_info!(
        "simple_example",
        simple_example::get_example_circuit().0,
        &params
    );
    check_circuit_info!("two_chip", two_chip::get_example_circuit().0, &params);
    check_circuit_info!("vector_mul", vector_mul::get_example_circuit().0, &params);
}

#[test]
fn test_circuit_reconstruction() -> Result<(), Error> {
    let mut params = load_default_kzg_params().expect("Failed to load default KZG params");
    params.downsize(8);
    let serialized_params =
        serialize_kzg_params(&params).expect("Failed to serialize KZG parameters");

    run_reconstruction!(
        "serialization",
        serialization::get_example_circuit(),
        &params,
        &serialized_params
    );
    run_reconstruction!(
        "simple_example",
        simple_example::get_example_circuit(),
        &params,
        &serialized_params
    );
    run_reconstruction!(
        "two_chip",
        two_chip::get_example_circuit(),
        &params,
        &serialized_params
    );
    run_reconstruction!(
        "vector_mul",
        vector_mul::get_example_circuit(),
        &params,
        &serialized_params
    );

    Ok(())
}
