
use ark_bn254::g1::G1Affine as ArkG1Affine;
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;

use group::GroupEncoding;
use hex::{encode, FromHex};
use std::io::{self};

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

use crate::params::{load_default_kzg_params, serialize_kzg_params};
use crate::public_inputs::PublicInputs;
use crate::{
    circuit::circuit_info::CircuitInfo, circuit::generate_circuit_info,
    circuit::reconstruct_cs_from_circuit_info, deserialize_circuit_and_verify,
};
use vk_gen_examples::examples::{
    circuit_layout, serialization, shuffle, shuffle_api, simple_example, two_chip, vector_mul,
};

#[test]
fn test_arkworks() -> Result<(), Box<dyn std::error::Error>> {
    let le_hex = "a7c40e6e753cfd404ff8e10e1352a3eb77c8e0495bf1d9b7c67410ce4f2a5a98";
    let bytes = Vec::from_hex(le_hex)?;
    let mut rdr = &bytes[..];
    let p = ArkG1Affine::deserialize_compressed(&mut rdr).expect("deserialize failed");
    if p.is_zero() {
        println!("point at infinity");
        return Ok(());
    }
    let x = p.x;
    let y = p.y;
    let x_le = x.into_bigint().to_bytes_le();
    let y_le = y.into_bigint().to_bytes_le();
    let mut uncompressed_le = Vec::with_capacity(64);
    uncompressed_le.extend_from_slice(&x_le);
    uncompressed_le.extend_from_slice(&y_le);

    println!("x (le)           = 0x{}", hex::encode(&x_le));
    println!("y (le)           = 0x{}", hex::encode(&y_le));
    println!("uncompressed (le)= 0x{}", hex::encode(&uncompressed_le));
    Ok(())
}

fn read<R: io::Read>(reader: &mut R) -> io::Result<G1Affine> {
    let mut compressed = <G1Affine as GroupEncoding>::Repr::default();
    reader.read_exact(compressed.as_mut())?;
    Option::from(G1Affine::from_bytes(&compressed))
        .ok_or_else(|| io::Error::other("Invalid point encoding in proof"))
}

#[test]
fn test_halo2curves() -> Result<(), Box<dyn std::error::Error>> {
    let le_hex = "a7c40e6e753cfd404ff8e10e1352a3eb77c8e0495bf1d9b7c67410ce4f2a5a98";
    let bytes = <Vec<u8>>::from_hex(le_hex)?;
    if bytes.len() != 32 {
        return Err("Invalid byte length".into());
    }

    let mut rdr = &bytes[..];
    let affine = read(&mut rdr)?;

    let x_le = affine.x.to_bytes().to_vec();
    let y_le = affine.y.to_bytes().to_vec();
    let mut uncompressed_le = Vec::with_capacity(64);
    uncompressed_le.extend_from_slice(&x_le);
    uncompressed_le.extend_from_slice(&y_le);

    println!("x (le)           = 0x{}", encode(&x_le));
    println!("y (le)           = 0x{}", encode(&y_le));
    println!("uncompressed (le)= 0x{}", encode(&uncompressed_le));

    Ok(())
}

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
            CircuitInfo::deserialize(&serialized_circuit_info).expect("Failed to deserialize");

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
        println!("proof bytes: 0x{}", hex::encode(proof.as_slice()));
        let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
        println!("vk bytes: 0x{}", hex::encode(vk_bytes.as_slice()));

        let circuit_info =
            generate_circuit_info($params, &circuit).expect("Failed to generate circuit info");
        let circuit_info_bytes = circuit_info
            .to_bytes()
            .expect("Failed to serialize circuit info");
        println!(
            "circuit info bytes: 0x{}",
            hex::encode(circuit_info_bytes.as_slice())
        );
        let deserialized_circuit_info =
            CircuitInfo::from_bytes(&circuit_info_bytes).expect("Failed to deserialize");

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

        let public_inputs_bytes = PublicInputs::<G1Affine>(instances).to_bytes();
        println!(
            "public inputs bytes: 0x{}",
            hex::encode(public_inputs_bytes.as_slice())
        );

        let public_inputs = PublicInputs::<G1Affine>::from_bytes(&public_inputs_bytes)
            .expect("Failed to deserialize public inputs")
            .0;

        verify_circuit(
            public_inputs,
            &$params.verifier_params(),
            &reconstructed_vk,
            &proof,
            KZG::GWC,
        )
        .expect("verify proof should not fail");

        let kzg = KZG::GWC.to_u8();

        deserialize_circuit_and_verify(
            $serialized_params.as_slice(),
            vk_bytes.as_slice(),
            &circuit_info_bytes,
            &public_inputs_bytes,
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
    params.downsize(4);
    let verifier_params = params.verifier_params();
    let serialized_params =
        serialize_kzg_params(&verifier_params).expect("Failed to serialize KZG parameters");

    println!(
        "serialized params: 0x{}",
        hex::encode(serialized_params.as_slice())
    );

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

#[test]
fn test_deserialize_circuit_and_verify() {
    // vector_mul circuit
    let serialized_params = hex_literal::hex!(
        "0400000042f8cfea72663b7832e47dc1fdeab56f2f1d07b729ce0a67a9f95480067c840de1800642e35c0a9fdd474e873eb42c6ceae6d8d8f43c0e035c9fbfb89bb32728303f01830dc2182d175d38ddb47e6cc2c2063b0831432043ac7994d29438082d9c8e35afccd69c2b897efd50d7ed0e62122388f41326dba4bc0d128ae0d14119"
    );

    let vk_bytes = hex_literal::hex!(
        "040401000000e8d6a310e68ff8ec0c23b3493ad971f39df348d914b69d900ef6bdb1a9380821a0d18c6d3fddc6df07b88dc384fed028707856b47f2ecf104a733b540541091054c1d5267ffcf0bb4847238fc935dff061a38e0c871a88849cf4d6460563c507b42083b1856a6aeb1c85d9942c94d017daa5a4ff5edfc46cf08ba1d025b0e3285adf9bf0d7ac95bb8db1cff4024ada370ee77158c0b3583d79e829e3445280057d2ddbb5c2d6dbc5f2f4d04cde7990d04398ffe4209787b59d4ca8cf3fdfca083bfafcc40b672a8f5e55f6e5b499cfb0f890dde2b36823a527c2d3eee7a1f52d935240d23b082f3a51d7891bc62a0f7af50b2ea077bf40037610850363338004203b2593d81f79267ccc50a960dd60a4ad849d0d22be1f321318a36a595f2a1542a3c0201d2e6111bb8e7e170542056c37d5e8de34633a62d5c5f1f7f3dd452b"
    );

    let circuit_info_bytes = hex_literal::hex!(
        "0b0c20acc86b4c84170be1ea86dfb0bf5d284c7bee72808a85412c71eeec572b2fbb0b208effc754694da2cb6df0dc36fe4a9bc7e3ec844490da918c007213c66bf786a38001b61dd63efa2807041eec04d2e53c1dcdef061216ff9f65a22d88b152b8d6559f994768be185bbb68e44116cb6d1017bab8dfe91dc3ddb28ed720139f34ea6505d4b098bb2b6a4f0d5ec7d96d3184666aaecda03d0d83cfe4fb06c7edccb9c5a22f720095cbbf541bd781e9d75cfd01d23ff3ca5674e05d85d001abce9688539e010404010000000403000000080100000000000000080100000000000000030000000001000100030a010000000001000000000a010100000001000000000a01020000000100000000010a03000000000100000000010a020000000001000000000405030000000005010000000005010100000005010200000000010c08020007080300030106030200000000"
    );

    let proof = hex_literal::hex!(
        "e9445cc7533f61fff8af036209735753b9276900d0b1812e91405ce65da07d20d8994f4c3db10d08f37a602e0f56258c624c6076d800678adfd0ecbad2fc3a2065db9386aa1d60c6c8ccffb869093fada5eb6797ba9488c8fa8b39f39d88ea0d8b987dbc98354df75153951b34d21fef0ec49e419453aa9eabb8397cf70c4e8945f3d19d0b85a80b1c92dd1f67742a65a1407676aae21846619e7683ba3681074fe0f929405e17fdb6b5457fa2796587349001fc43ee6726ef6473a62d772e270c4f6c0720fbd0cc9b142f6b7019cce18ffbb071348b7252d92c15ed49cb34af5fb50e30a6f2ae37b39bbc5e0f08f511623fc2e347f9dbc241b7676af8c2068f4e424a79cdf9e47d3f81213b7ce0754e22a5900bc034d9ec14eb976f2e4fe68f13a964e497d8550450f29c3d207d1319e41d325463add88986caa6226d3f5a071c1a237da662f8bc7044c930ba01e78ebab10c8f3750ce3875ade4c17613f629d469b3c80240d084f8eb7c00d349f1ec2eb923405d065c45e05972117810750c129a65213a381020350769823427aa691c79b77591373c8c9a19ee97717bda1bd2e5fe1e693cea645a56976dac736f1e4729ffc503392660cff16d21c64679144b8ad3b2f7ffd36e26837178cdd403266fe5ef05eee9eccf87032c2be6327007fad06835aceec94fcd5018e0d7001da60be35da0a23d43f702c6a8da7c40433047344f70808328501fce9f1920c3f54187c36e36c4d3d410fe76295a2f0afe07e040ec38b721e1fdb068c0eea9e5ec3b88579674b13a9471f7e8f2d6e82a5e00bf6c1f64443eaac6a3e772d283e6a35839574d39fa183fa8ed0dbb87beb71e2412fe1918f814d4ad50bb2001a6d0afb2c98bbce25b1d516896fa431853965812000be23e6303955802b8c503385837aaf3a84459d99d426d2723d63a20d74c2c91afafcce1aa44c1faaaa5f088da984c557cd591fa0e8bd3ef31ad1c128b1e21e19032fd9c419d73a070165530851f8ddbfab0c6a0ee795428bbbe6ef74cbd2c99ffe15922ee1a3b9ae82e99d5783ad1d3804b5df5ececa5898a58167a426f0ff534a7c85ca4603eb202f5e6ee2993b5bf74ea2fd930687946ff421e0ed8b40f881fb309f422e050f35184f65e4f719c2f0fb8a68ee5de10fc474532d00c2122657efdc65431f313ec8d02ed8f017b9bb14fff3910dfc58f78c5f8f17f32ca1c8fb4abbcb1978e8c5f1d783025eb19fb8580e4f50bb3755136ff1a2c0ac903296bb6136ecf03ba35e23496dfd4d77b728532cb5b41ba46fc489926ddb5951a26b82e74bf0fd684b4f4a1c4728eedece37c52a970f30e5915fb931d804014992ba09392b14eca34c6a8e3915dac6afc2ef43041ec6691f4c7769bf230b9016614391af4f7d9df348ee7a0005c110e0563a65073f5f7383abc98912d8e249e3a13e0242be684a69ebe87cf7da07ede3ba9fd7041db88f3cba0469bd3b582393a9e"
    );

    let public_inputs_bytes = hex_literal::hex!(
        "0103200600000000000000000000000000000000000000000000000000000000000000200600000000000000000000000000000000000000000000000000000000000000200600000000000000000000000000000000000000000000000000000000000000"
    );

    let result = deserialize_circuit_and_verify(
        serialized_params.as_slice(), // &[u8]
        vk_bytes.as_slice(),
        circuit_info_bytes.as_slice(),
        public_inputs_bytes.as_slice(),
        proof.as_slice(),
        0, // kzg_variant = 0 (GWC)
        None,
    );

    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}
