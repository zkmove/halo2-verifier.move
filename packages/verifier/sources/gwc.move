module halo2_verifier::gwc {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bn254_algebra::{G1, G2, Gt, Fr};

    use halo2_common::msm::{Self, MSM};
    use halo2_common::params::{Self, Params};
    use halo2_common::query::{Self, VerifierQuery};
    use halo2_verifier::transcript::{Self, Transcript};
    
    public fun verify(
        params: &Params,
        transcript: &mut Transcript,
        queries: &vector<VerifierQuery>
    ): bool {
        let v = transcript::squeeze_challenge(transcript);
        let sets = construct_intermediate_sets(queries);
        let set_len = vector::length(&sets);
        let w = transcript::read_n_point(transcript, set_len);
        let u = transcript::squeeze_challenge(transcript);

        // commitment_multi = C(0)+ u * C(1) + u^2 * C(2) + .. + u^n * C(n)
        let commitment_multi = msm::empty_msm();
        // eval_multi = E(0)+ u * E(1) + u^2 * E(2) + .. + u^n * E(n)
        let eval_multi = crypto_algebra::zero<Fr>();
        // witness = u^0 * w_0 + u^1 * w_1 + u^2 * w_2 + .. u^n * w_n
        let witness = msm::empty_msm();
        // witness_with_aux = u^0 * z_0 * w_0 + u^1 * z_1 * w_1 + u^2 * z_2 * w_2 + .. u^n * z_n * w_n
        let witness_with_aux = msm::empty_msm();

        let power_of_u = crypto_algebra::one<Fr>();

        vector::zip_ref(&sets, &w, |commitment_at_a_point, w_i| {
            let z = query::point(vector::borrow(commitment_at_a_point, 0));

            // C(i) = sum_j(v^(j-1) * cm(j))
            let commitment_acc = msm::empty_msm();
            // E(i) = sum_j(v^(j-1) * s(j))
            let eval_acc = crypto_algebra::zero<Fr>();
            {
                let power_of_v = crypto_algebra::one<Fr>();
                vector::for_each_ref(commitment_at_a_point, |q| {
                    let c = query::multiply(query::commitment(q), &power_of_v);
                    let eval = crypto_algebra::mul<Fr>(&power_of_v, query::eval(q));
                    msm::add_msm(&mut commitment_acc, &c);
                    eval_acc = crypto_algebra::add<Fr>(&eval_acc, &eval);
                    power_of_v = crypto_algebra::mul<Fr>(&power_of_v, &v);
                });
            };
            msm::scale(&mut commitment_acc, &power_of_u);
            msm::add_msm(&mut commitment_multi, &commitment_acc);
            eval_multi = crypto_algebra::add<Fr>(&eval_multi, &crypto_algebra::mul<Fr>(&power_of_u, &eval_acc));
            msm::append_term(&mut witness_with_aux, crypto_algebra::mul<Fr>(&power_of_u, z), *w_i);
            msm::append_term(&mut witness, power_of_u, *w_i);

            power_of_u = crypto_algebra::mul(&power_of_u, &u);
        });

        // then we verify:
        // e(witness, [x]@2) = e(commitment_multi + witness_with_aux - [eval_multi]@1, [1]@2)
        verify_inner(params, witness, commitment_multi, eval_multi, witness_with_aux)
    }

    // e(witness, [x]@2) = e(commitment_multi + witness_with_aux - [eval_multi]@1, [1]@2)
    fun verify_inner(
        params: &Params,
        witness: MSM,
        commitment_multi: MSM,
        eval_multi: Element<Fr>,
        witness_with_aux: MSM
    ): bool {
        msm::add_msm(&mut commitment_multi, &witness_with_aux);
        msm::append_term(&mut commitment_multi, eval_multi, crypto_algebra::neg(params::g(params)));
        let right = msm::eval(&commitment_multi);
        let left = msm::eval(&witness);

        let g1s = vector::singleton(left);
        vector::push_back(&mut g1s, right);
        let g2s = vector::singleton(*params::s_g2(params));
        vector::push_back(&mut g2s, crypto_algebra::neg(params::g2(params)));

        let pairing_result = crypto_algebra::multi_pairing<G1, G2, Gt>(&g1s, &g2s);
        crypto_algebra::eq(&pairing_result, &crypto_algebra::zero())
    }

    fun construct_intermediate_sets(queries: &vector<VerifierQuery>): vector<vector<VerifierQuery>> {
        let sets = vector::empty();
        vector::for_each_ref(queries, |q| {
            let point = query::point(q);
            let (find, index) = vector::find(&sets, |s| {
                let s: &vector<VerifierQuery> = s;
                crypto_algebra::eq(query::point(vector::borrow(s, 0)), point)
            });
            if (find) {
                vector::push_back(vector::borrow_mut(&mut sets, index), *q);
            } else {
                vector::push_back(&mut sets, vector::singleton(*q));
            };
        });
        sets
    }
}
