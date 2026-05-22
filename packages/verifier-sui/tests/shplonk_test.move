// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::shplonk_test {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils::serialize_g1;
    use halo2_common::params;
    use halo2_common::query;
    use halo2_verifier::shplonk;
    use halo2_verifier::transcript;

    fun scalar(value: u64): Element<bn254::Scalar> {
        bn254::scalar_from_u64(value)
    }

    fun sample_params(): params::Params {
        let g1 = bn254::g1_generator();
        let g2 = bn254::g2_generator();
        params::new(g1, g2, bn254::g2_mul(&scalar(5), &g2))
    }

    fun transcript_with_h1_h2(): transcript::Transcript {
        let witness = bn254::g1_mul(&scalar(3), &bn254::g1_generator());
        let mut proof = serialize_g1(&witness);
        vector::append(&mut proof, serialize_g1(&witness));
        transcript::new(proof)
    }

    #[test]
    fun test_verify_single_opening() {
        let params = sample_params();
        let g = bn254::g1_generator();
        let commitment = bn254::g1_mul(&scalar(16), &g);
        let queries = vector[query::new_commitment(commitment, scalar(2), scalar(7))];
        let mut transcript = transcript_with_h1_h2();

        assert!(shplonk::verify(&params, &mut transcript, &queries), 1000);
        assert!(transcript::proof_remaining_len(&transcript) == 0, 1001);
    }

    #[test]
    fun test_verify_rejects_wrong_eval() {
        let params = sample_params();
        let g = bn254::g1_generator();
        let commitment = bn254::g1_mul(&scalar(16), &g);
        let queries = vector[query::new_commitment(commitment, scalar(2), scalar(8))];
        let mut transcript = transcript_with_h1_h2();

        assert!(!shplonk::verify(&params, &mut transcript, &queries), 2000);
    }
}
