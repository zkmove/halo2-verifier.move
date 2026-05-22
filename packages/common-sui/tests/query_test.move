// Copyright (c) zkMove Authors

#[test_only]
module halo2_common::query_test {
    use sui::bn254;
    use sui::group_ops;
    use halo2_common::msm;
    use halo2_common::query;

    #[test]
    fun test_new_commitment_accessors_and_multiply() {
        let g = bn254::g1_generator();
        let point = bn254::scalar_from_u64(5);
        let eval = bn254::scalar_from_u64(9);
        let scale = bn254::scalar_from_u64(3);
        let q = query::new_commitment(g, point, eval);

        assert!(group_ops::equal(query::point(&q), &point));
        assert!(group_ops::equal(query::eval(&q), &eval));

        let product = query::multiply(query::commitment(&q), &scale);
        let expected = bn254::g1_mul(&scale, &g);
        assert!(group_ops::equal(&msm::eval(&product), &expected));
    }

    #[test]
    fun test_new_msm_accessors_and_multiply() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let point = bn254::scalar_from_u64(11);
        let eval = bn254::scalar_from_u64(13);
        let scale = bn254::scalar_from_u64(5);

        let mut base_msm = msm::empty_msm();
        msm::append_term(&mut base_msm, bn254::scalar_from_u64(2), g);
        msm::append_term(&mut base_msm, bn254::scalar_from_u64(3), two_g);

        let q = query::new_msm(base_msm, point, eval);
        assert!(group_ops::equal(query::point(&q), &point));
        assert!(group_ops::equal(query::eval(&q), &eval));

        let product = query::multiply(query::commitment(&q), &scale);
        let expected = bn254::g1_mul(&bn254::scalar_from_u64(40), &g);
        assert!(group_ops::equal(&msm::eval(&product), &expected));
    }

    #[test]
    fun test_eq_commit_reference_for_commitments() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let point = bn254::scalar_from_u64(5);
        let eval = bn254::scalar_from_u64(9);

        let a = query::new_commitment(g, point, eval);
        let b = query::new_commitment(g, point, eval);
        let c = query::new_commitment(two_g, point, eval);

        assert!(query::eq_commit_reference(query::commitment(&a), query::commitment(&b)));
        assert!(!query::eq_commit_reference(query::commitment(&a), query::commitment(&c)));
    }

    #[test]
    fun test_eq_commit_reference_for_msms() {
        let g = bn254::g1_generator();
        let two_g = bn254::g1_mul(&bn254::scalar_from_u64(2), &g);
        let point = bn254::scalar_from_u64(5);
        let eval = bn254::scalar_from_u64(9);

        let mut msm_a = msm::empty_msm();
        msm::append_term(&mut msm_a, bn254::scalar_from_u64(2), g);

        let mut msm_b = msm::empty_msm();
        msm::append_term(&mut msm_b, bn254::scalar_from_u64(2), g);

        let mut msm_c = msm::empty_msm();
        msm::append_term(&mut msm_c, bn254::scalar_from_u64(2), two_g);

        let a = query::new_msm(msm_a, point, eval);
        let b = query::new_msm(msm_b, point, eval);
        let c = query::new_msm(msm_c, point, eval);

        assert!(query::eq_commit_reference(query::commitment(&a), query::commitment(&b)));
        assert!(!query::eq_commit_reference(query::commitment(&a), query::commitment(&c)));
    }

    #[test]
    fun test_eq_commit_reference_cross_kind_is_false() {
        let g = bn254::g1_generator();
        let point = bn254::scalar_from_u64(5);
        let eval = bn254::scalar_from_u64(9);

        let commitment_query = query::new_commitment(g, point, eval);

        let mut base_msm = msm::empty_msm();
        msm::append_term(&mut base_msm, bn254::scalar_from_u64(1), g);
        let msm_query = query::new_msm(base_msm, point, eval);

        assert!(!query::eq_commit_reference(query::commitment(&commitment_query), query::commitment(&msm_query)));
        assert!(!query::eq_commit_reference(query::commitment(&msm_query), query::commitment(&commitment_query)));
    }
}
