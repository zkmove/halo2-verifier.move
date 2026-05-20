// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::vanishing_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::bn254_utils::{serialize_fr, serialize_g1};
    use halo2_common::msm;
    use halo2_common::query;
    use halo2_verifier::transcript;
    use halo2_verifier::vanishing;

    fun scalar(value: u64): group_ops::Element<bn254::Scalar> {
        bn254::scalar_from_u64(value)
    }

    fun proof_with_points_and_scalar(
        random_commitment: &group_ops::Element<bn254::G1>,
        h1: &group_ops::Element<bn254::G1>,
        h2: &group_ops::Element<bn254::G1>,
        random_eval: &group_ops::Element<bn254::Scalar>,
    ): vector<u8> {
        let mut proof = serialize_g1(random_commitment);
        vector::append(&mut proof, serialize_g1(h1));
        vector::append(&mut proof, serialize_g1(h2));
        vector::append(&mut proof, serialize_fr(random_eval));
        proof
    }

    #[test]
    fun test_read_commitments_and_h_commitments_accessor() {
        let g = bn254::g1_generator();
        let h1 = bn254::g1_mul(&scalar(2), &g);
        let h2 = bn254::g1_mul(&scalar(3), &g);
        let random_eval = scalar(7);
        let proof = proof_with_points_and_scalar(&g, &h1, &h2, &random_eval);
        let mut transcript = transcript::new(proof);

        let constructed = vanishing::read_commitments_before_y(&mut transcript);
        assert!(vanishing::h_commitments(&constructed).length() == 0, 1000);

        let constructed = vanishing::read_commitments_after_y(constructed, &mut transcript, 2);
        let h_commitments = vanishing::h_commitments(&constructed);
        assert!(h_commitments.length() == 2, 1001);
        assert!(group_ops::equal(&h_commitments[0], &h1));
        assert!(group_ops::equal(&h_commitments[1], &h2));
        assert!(transcript::proof_remaining_len(&transcript) == 32, 1002);
    }

    #[test]
    fun test_h_eval_and_queries() {
        let g = bn254::g1_generator();
        let h1 = g;
        let h2 = bn254::g1_mul(&scalar(2), &g);
        let random_eval = scalar(7);
        let proof = proof_with_points_and_scalar(&g, &h1, &h2, &random_eval);
        let mut transcript = transcript::new(proof);

        let constructed = vanishing::read_commitments_before_y(&mut transcript);
        let constructed = vanishing::read_commitments_after_y(constructed, &mut transcript, 2);
        let partial = vanishing::evaluate_after_x(constructed, &mut transcript);
        assert!(transcript::proof_remaining_len(&transcript) == 0, 2000);

        let expressions = vector[scalar(1), scalar(2)];
        let y = scalar(10);
        let x = scalar(5);
        let xn = scalar(4);
        let evaluated = vanishing::h_eval(partial, &expressions, &y, &xn);

        let mut queries = vector[];
        vanishing::queries(evaluated, &mut queries, &x);
        assert!(queries.length() == 2, 2001);

        let h_query = &queries[0];
        assert!(group_ops::equal(query::point(h_query), &x));
        assert!(group_ops::equal(query::eval(h_query), &scalar(4)));

        let h_msm = query::multiply(query::commitment(h_query), &scalar(1));
        let expected_h_commitment = bn254::g1_mul(&scalar(9), &g);
        assert!(group_ops::equal(&msm::eval(&h_msm), &expected_h_commitment));

        let random_query = &queries[1];
        assert!(group_ops::equal(query::point(random_query), &x));
        assert!(group_ops::equal(query::eval(random_query), &random_eval));
        let random_msm = query::multiply(query::commitment(random_query), &scalar(1));
        assert!(group_ops::equal(&msm::eval(&random_msm), &g));
    }

    #[test, expected_failure]
    fun test_read_commitments_after_y_short_proof_aborts() {
        let g = bn254::g1_generator();
        let mut transcript = transcript::new(serialize_g1(&g));
        let constructed = vanishing::read_commitments_before_y(&mut transcript);
        let _ = vanishing::read_commitments_after_y(constructed, &mut transcript, 1);
    }
}
