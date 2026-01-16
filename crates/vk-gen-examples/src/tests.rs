use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use rand::rngs::mock::StepRng;

use crate::examples::{
    circuit_layout, serialization, shuffle, shuffle_api, simple_example, two_chip, vector_mul,
};
use shape_generator::{generate_circuit_info, CircuitInfo};

fn create_test_params(k: u32) -> ParamsKZG<Bn256> {
    let rng = StepRng::new(0, 1);
    ParamsKZG::<Bn256>::setup(k, rng)
}

#[test]
fn test_circuit_info_serialization() {
    let params = create_test_params(8);

    // Test circuit_layout
    {
        let circuit = circuit_layout::get_example_circuit::<Fr>();
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ circuit_layout passed");
    }

    // Test serialization
    {
        let circuit = serialization::get_example_circuit().0;
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ serialization passed");
    }

    // Test shuffle
    {
        let circuit = shuffle::get_example_circuit();
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ shuffle passed");
    }

    // Test shuffle_api
    {
        let circuit = shuffle_api::get_example_circuit();
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ shuffle_api passed");
    }

    // Test simple_example
    {
        let circuit = simple_example::get_example_circuit().0;
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ simple_example passed");
    }

    // Test two_chip
    {
        let circuit = two_chip::get_example_circuit().0;
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ two_chip passed");
    }

    // Test vector_mul
    {
        let circuit = vector_mul::get_example_circuit().0;
        let circuit_info =
            generate_circuit_info(&params, &circuit).expect("Failed to generate circuit info");

        let serialized_circuit_info = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let deserialized_circuit_info = CircuitInfo::deserialize(serialized_circuit_info)
            .expect("Failed to deserialize circuit info");
        assert_eq!(
            circuit_info, deserialized_circuit_info,
            "Deserialized circuit info does not match original"
        );
        println!("✓ vector_mul passed");
    }
}
