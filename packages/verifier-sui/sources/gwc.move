// Copyright (c) zkMove Authors

module halo2_verifier::gwc {
    use sui::bn254;
    use sui::group_ops::{Self, Element};
    use halo2_common::msm::{Self, MSM};
    use halo2_common::params::{Self, Params};
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::transcript::{Self, Transcript};

    public fun verify(
        params: &Params,
        transcript: &mut Transcript,
        queries: &vector<VerifierQuery>,
    ): bool {
        let v = transcript::squeeze_challenge(transcript);
        let sets = construct_intermediate_sets(queries);
        let set_len = sets.length();
        let w = transcript::read_n_point(transcript, set_len);
        let u = transcript::squeeze_challenge(transcript);

        let mut commitment_multi = msm::empty_msm();
        let mut eval_multi = bn254::scalar_zero();
        let mut witness = msm::empty_msm();
        let mut witness_with_aux = msm::empty_msm();
        let mut power_of_u = bn254::scalar_one();

        let mut i = 0;
        while (i < set_len) {
            let commitment_at_a_point = &sets[i];
            let w_i = w[i];
            let z = query::point(&commitment_at_a_point[0]);

            let mut commitment_acc = msm::empty_msm();
            let mut eval_acc = bn254::scalar_zero();
            let mut power_of_v = bn254::scalar_one();
            let mut j = 0;
            while (j < commitment_at_a_point.length()) {
                let q = &commitment_at_a_point[j];
                let c = query::multiply(query::commitment(q), &power_of_v);
                let eval = bn254::scalar_mul(&power_of_v, query::eval(q));
                msm::add_msm(&mut commitment_acc, &c);
                eval_acc = bn254::scalar_add(&eval_acc, &eval);
                power_of_v = bn254::scalar_mul(&power_of_v, &v);
                j = j + 1;
            };

            msm::scale(&mut commitment_acc, &power_of_u);
            msm::add_msm(&mut commitment_multi, &commitment_acc);
            eval_multi = bn254::scalar_add(&eval_multi, &bn254::scalar_mul(&power_of_u, &eval_acc));
            msm::append_term(&mut witness_with_aux, bn254::scalar_mul(&power_of_u, z), w_i);
            msm::append_term(&mut witness, power_of_u, w_i);

            power_of_u = bn254::scalar_mul(&power_of_u, &u);
            i = i + 1;
        };

        verify_inner(params, witness, commitment_multi, eval_multi, witness_with_aux)
    }

    fun verify_inner(
        params: &Params,
        witness: MSM,
        mut commitment_multi: MSM,
        eval_multi: Element<bn254::Scalar>,
        witness_with_aux: MSM,
    ): bool {
        msm::add_msm(&mut commitment_multi, &witness_with_aux);
        msm::append_term(&mut commitment_multi, eval_multi, bn254::g1_neg(params::g(params)));
        let right = msm::eval(&commitment_multi);
        let left = msm::eval(&witness);

        let pairing_result = bn254::gt_add(
            &bn254::pairing(&left, params::s_g2(params)),
            &bn254::pairing(&right, &bn254::g2_neg(params::g2(params))),
        );
        group_ops::equal(&pairing_result, &bn254::gt_identity())
    }

    fun construct_intermediate_sets(queries: &vector<VerifierQuery>): vector<vector<VerifierQuery>> {
        let mut sets: vector<vector<VerifierQuery>> = vector[];
        let mut i = 0;
        while (i < queries.length()) {
            let q = queries[i];
            let point = query::point(&q);
            let mut found = false;
            let mut index = 0;
            let mut j = 0;
            while (j < sets.length()) {
                let set: &vector<VerifierQuery> = &sets[j];
                if (group_ops::equal(query::point(&set[0]), point)) {
                    found = true;
                    index = j;
                    j = sets.length();
                } else {
                    j = j + 1;
                };
            };

            if (found) {
                vector::push_back(&mut sets[index], q);
            } else {
                vector::push_back(&mut sets, vector[q]);
            };
            i = i + 1;
        };
        sets
    }
}
