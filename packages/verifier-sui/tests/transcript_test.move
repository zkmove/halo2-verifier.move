// Copyright (c) zkMove Authors

#[test_only]
module halo2_verifier::transcript_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::bn254_utils;
    use halo2_verifier::transcript;

    fun scalar(value: u64): group_ops::Element<bn254::Scalar> {
        bn254::scalar_from_u64(value)
    }

    #[test]
    fun test_init_and_empty_challenge_is_deterministic() {
        let mut a = transcript::new(vector[]);
        let mut b = transcript::new(vector[]);

        assert!(transcript::proof_remaining_len(&a) == 0, 1000);
        assert!(group_ops::equal(
            &transcript::squeeze_challenge(&mut a),
            &transcript::squeeze_challenge(&mut b),
        ));
    }

    #[test]
    fun test_common_scalar_matches_read_scalar() {
        let value = scalar(42);
        let scalar_bytes = bn254_utils::serialize_fr(&value);

        let mut read_transcript = transcript::new(copy scalar_bytes);
        let read_value = transcript::read_scalar(&mut read_transcript);
        assert!(group_ops::equal(&read_value, &value));
        assert!(transcript::proof_remaining_len(&read_transcript) == 0, 1001);

        let mut common_transcript = transcript::new(vector[]);
        transcript::common_scalar(&mut common_transcript, value);

        assert!(group_ops::equal(
            &transcript::squeeze_challenge(&mut read_transcript),
            &transcript::squeeze_challenge(&mut common_transcript),
        ));
    }

    #[test]
    fun test_read_n_scalar_and_squeeze_n_challenges() {
        let a = scalar(1);
        let b = scalar(2);
        let mut proof = bn254_utils::serialize_fr(&a);
        vector::append(&mut proof, bn254_utils::serialize_fr(&b));

        let mut t = transcript::new(proof);
        let scalars = transcript::read_n_scalar(&mut t, 2);
        assert!(scalars.length() == 2, 1002);
        assert!(group_ops::equal(&scalars[0], &a));
        assert!(group_ops::equal(&scalars[1], &b));
        assert!(transcript::proof_remaining_len(&t) == 0, 1003);

        let challenges = transcript::squeeze_n_challenges(&mut t, 2);
        assert!(challenges.length() == 2, 1004);
        assert!(!group_ops::equal(&challenges[0], &challenges[1]));
    }

    #[test]
    fun test_common_point_matches_read_point() {
        let point = bn254::g1_generator();
        let point_bytes = bn254_utils::serialize_g1(&point);

        let mut read_transcript = transcript::new(copy point_bytes);
        let read_point = transcript::read_point(&mut read_transcript);
        assert!(group_ops::equal(&read_point, &point));
        assert!(transcript::proof_remaining_len(&read_transcript) == 0, 1005);

        let mut common_transcript = transcript::new(vector[]);
        transcript::common_point(&mut common_transcript, point);

        assert!(group_ops::equal(
            &transcript::squeeze_challenge(&mut read_transcript),
            &transcript::squeeze_challenge(&mut common_transcript),
        ));
    }

    #[test]
    fun test_read_n_point() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&scalar(2), &g);
        let mut proof = bn254_utils::serialize_g1(&g);
        vector::append(&mut proof, bn254_utils::serialize_g1(&two_g));

        let mut t = transcript::new(proof);
        let points = transcript::read_n_point(&mut t, 2);
        assert!(points.length() == 2, 1006);
        assert!(group_ops::equal(&points[0], &g));
        assert!(group_ops::equal(&points[1], &two_g));
        assert!(transcript::proof_remaining_len(&t) == 0, 1007);
    }

    #[test, expected_failure]
    fun test_read_scalar_short_buffer_aborts() {
        let mut t = transcript::new(vector[1, 2, 3]);
        let _ = transcript::read_scalar(&mut t);
    }

    #[test, expected_failure]
    fun test_read_point_short_buffer_aborts() {
        let mut t = transcript::new(vector[1, 2, 3]);
        let _ = transcript::read_point(&mut t);
    }
}
