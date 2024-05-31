module halo2_verifier::shplonk {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::comparator::{compare_u8_vector, is_greater_than};
    use aptos_std::bn254_algebra::{G1, G2, Gt, Fr};

    use halo2_common::msm;
    use halo2_common::params::{Self, Params};
    use halo2_common::query::{Self, VerifierQuery, CommitmentReference};
    use halo2_common::bn254_utils;
    use halo2_verifier::transcript::{Self, Transcript};

    #[test_only]
    use aptos_std::crypto_algebra::{enable_cryptography_algebra_natives};

    #[test_only]
    use std::option;

    struct CommitmentRotationSet has copy, drop {
        rotations: vector<Element<Fr>>,
        commitment: CommitmentReference,
    }

    struct RotationSetCommitment has copy, drop {
        rotations: vector<Element<Fr>>,
        commitments: vector<CommitmentReference>,
    }

    struct Commitment has copy, drop {
        commitment: CommitmentReference,
        evals: vector<Element<Fr>>,
    }

    struct RotationSet has copy, drop {
        points: vector<Element<Fr>>,
        commitments: vector<Commitment>,
    }

    public fun verify(
        params: &Params,
        transcript: &mut Transcript,
        queries: &vector<VerifierQuery>
    ): bool {
        let (rotation_sets, super_point_set) = construct_intermediate_sets(queries);

        let y = transcript::squeeze_challenge(transcript);
        let v = transcript::squeeze_challenge(transcript);

        let h1 = transcript::read_point(transcript);
        let u = transcript::squeeze_challenge(transcript);
        let h2 = transcript::read_point(transcript);

        let z_0_diff_inverse: Element<Fr> = crypto_algebra::zero();
        let z_0: Element<Fr> = crypto_algebra::zero();
        let outer_msm = msm::empty_msm();
        let r_outer_acc: Element<Fr> = crypto_algebra::zero();

        let power_of_v = crypto_algebra::one<Fr>();
        vector::enumerate_ref(&rotation_sets, |i, rotation_set| {
            let rotation_set: &RotationSet = rotation_set;
            let diffs: vector<Element<Fr>> = vector::empty();
            vector::for_each_ref(&super_point_set, |point| {
                let point: &Element<Fr> = point;

                let (find, _) = vector::find(&rotation_set.points, |s| {
                    let s: &Element<Fr> = s;
                    crypto_algebra::eq(s, point)
                });

                if (!find) {
                    vector::push_back(&mut diffs, *point);
                };
            });

            let z_diff_i = evaluate_vanishing_polynomial(diffs, u);

            // normalize coefficients by the coefficient of the first commitment
            if (i == 0) {
                z_0 = evaluate_vanishing_polynomial(rotation_set.points, u);
                z_0_diff_inverse = bn254_utils::invert(&z_diff_i);
                z_diff_i = crypto_algebra::one<Fr>();
            } else {
                z_diff_i = crypto_algebra::mul(&z_diff_i, &z_0_diff_inverse);
            };

            let inner_msm = msm::empty_msm();
            let r_inner_acc = crypto_algebra::zero();

            let power_of_y = crypto_algebra::one<Fr>();
            vector::for_each_ref(&rotation_set.commitments, |commitment_data| {
                let commitment_data: &Commitment = commitment_data;

                // calculate low degree equivalent
                let r_x = lagrange_interpolate(rotation_set.points, commitment_data.evals);
                let r_eval = crypto_algebra::mul(&power_of_y, &eval_polynomial(r_x, u));
                r_inner_acc = crypto_algebra::add(&r_inner_acc, &r_eval);

                let c = query::multiply(&commitment_data.commitment, &power_of_y);
                msm::add_msm(&mut inner_msm, &c);

                power_of_y = crypto_algebra::mul(&power_of_y, &y);
            });

            msm::scale(&mut inner_msm, &crypto_algebra::mul(&power_of_v, &z_diff_i));
            msm::add_msm(&mut outer_msm, &inner_msm);
            r_outer_acc = crypto_algebra::add(&r_outer_acc, &crypto_algebra::mul(&power_of_v, &crypto_algebra::mul(&r_inner_acc, &z_diff_i)));

            power_of_v = crypto_algebra::mul(&power_of_v, &v);
        });

        let left = msm::empty_msm();
        msm::append_term(&mut left, crypto_algebra::one(), h2);
        let left = msm::eval(&left);

        let g1 = *params::g(params);
        msm::append_term(&mut outer_msm, crypto_algebra::neg(&r_outer_acc), g1);
        msm::append_term(&mut outer_msm, crypto_algebra::neg(&z_0), h1);
        msm::append_term(&mut outer_msm, u, h2);
        let right = msm::eval(&outer_msm);

        let g1s = vector::singleton(left);
        vector::push_back(&mut g1s, right);
        let g2s = vector::singleton(*params::s_g2(params));
        vector::push_back(&mut g2s, crypto_algebra::neg(params::g2(params)));

        let pairing_result = crypto_algebra::multi_pairing<G1, G2, Gt>(&g1s, &g2s);
        crypto_algebra::eq(&pairing_result, &crypto_algebra::zero())
    }

    fun construct_intermediate_sets(queries: &vector<VerifierQuery>): (vector<RotationSet>, vector<Element<Fr>>) {
        let super_point_set: vector<Element<Fr>> = vector::empty();

        // Collect rotation sets for each commitment
        // Example elements in the vector:
        // (C_0, {r_5}),
        // (C_1, {r_1, r_2, r_3}),
        // (C_2, {r_2, r_3, r_4}),
        // (C_3, {r_2, r_3, r_4}),
        // ...
        let commitment_rotation_set_map: vector<CommitmentRotationSet> = vector::empty();
        vector::for_each_ref(queries, |q| {
            let point = *query::point(q);
            let commitment = *query::commitment(q);
            vector::push_back(&mut super_point_set, point);

            let (find, index) = vector::find(&commitment_rotation_set_map, |s| {
                let s: CommitmentRotationSet = *s;
                query::eq_commit_reference(&s.commitment, &commitment)
            });
            if (find) {
                let s = vector::borrow_mut(&mut commitment_rotation_set_map, index);
                vector::push_back(&mut s.rotations, point);
            } else {
                vector::push_back(&mut commitment_rotation_set_map, CommitmentRotationSet {
                    rotations: vector[point],
                    commitment,
                });
            };
        });

        // Implement btree for rotations in commitment_rotation_set_map
        vector::for_each_mut(&mut commitment_rotation_set_map, |set| {
            let set: &mut CommitmentRotationSet = set;
            set.rotations = remove_duplicate_and_sort(&set.rotations);
        });

        // Flatten rotation sets and collect commitments that opens against each commitment set
        // Example elements in the vector:
        // {r_5}: [C_0],
        // {r_1, r_2, r_3} : [C_1]
        // {r_2, r_3, r_4} : [C_2, C_3],
        // ...
        let rotation_set_commitment_map: vector<RotationSetCommitment> = vector::empty();
        vector::for_each_ref(&commitment_rotation_set_map, |c| {
            let c: &CommitmentRotationSet = c;
            let (find, index) = vector::find(&rotation_set_commitment_map, |s| {
                let s: RotationSetCommitment = *s;
                bn254_utils::eq_elements<Fr>(&s.rotations, &c.rotations)
            });
            if (find) {
                let s = vector::borrow_mut(&mut rotation_set_commitment_map, index);
                vector::push_back(&mut s.commitments, c.commitment);
            } else {
                vector::push_back(&mut rotation_set_commitment_map, RotationSetCommitment {
                    rotations: c.rotations,
                    commitments: vector[c.commitment],
                });
            };
        });

        let rotation_sets = vector::map_ref(&rotation_set_commitment_map, |rotation_set| {
            let rotation_set: RotationSetCommitment = *rotation_set;
            let rotations = rotation_set.rotations;
            let commitments = vector::map_ref(&rotation_set.commitments, |commitment| {
                let commitment: CommitmentReference = *commitment;
                let evals = vector::map_ref(&rotations, |rotation| {
                    let rotation: Element<Fr> = *rotation;

                    let (_, index) = vector::find(queries, |q| {
                        let q: &VerifierQuery = q;
                        query::eq_commit_reference(&commitment, query::commitment(q)) && crypto_algebra::eq(&rotation, query::point(q))
                    });

                    *query::eval(vector::borrow(queries, index))
                });

                Commitment {
                    commitment,
                    evals,
                }
            });

            RotationSet {
                commitments,
                points: rotations
            }
        });

        super_point_set = remove_duplicate_and_sort(&super_point_set);

        (rotation_sets, super_point_set)
    }

    fun lagrange_interpolate(points: vector<Element<Fr>>, evals: vector<Element<Fr>>): vector<Element<Fr>> {
        let points_len = vector::length(&points);
        let evals_len = vector::length(&evals);
        assert!(points_len == evals_len, 100);

        if (points_len == 1) {
            return vector[*vector::borrow(&evals, 0)]
        };

        let denoms = vector::empty();
        let j = 0;
        while (j < vector::length(&points)) {
            let x_j = vector::borrow(&points, j);
            let k = 0;
            let denom = vector::empty();
            while (k < vector::length(&points)) {
                let x_k = vector::borrow(&points, k);
                if (k != j) {
                    vector::push_back(&mut denom, bn254_utils::invert(&crypto_algebra::sub(x_j, x_k)));
                };
                k = k + 1;
            };
            vector::push_back(&mut denoms, denom);
            j = j + 1;
        };

        // Create final_poly with 0 points
        let i = 0;
        let final_poly: vector<Element<Fr>> = vector::empty();
        while (i < points_len) {
            vector::push_back(&mut final_poly, crypto_algebra::zero());
            i = i + 1;
        };

        let j = 0;
        while (j < points_len) {
            let denoms = vector::borrow(&denoms, j);
            let eval = vector::borrow(&evals, j);

            let tmp = vector[crypto_algebra::one()];
            let product = vector::empty();

            let k = 0;
            let denom_idx = 0;
            while(k < points_len) {

                if (k != j) {
                    let x_k = vector::borrow(&points, k);
                    let denom = vector::borrow(denoms, denom_idx);

                    let t = 0;
                    let product_len = vector::length(&product);
                    let tmp_len = vector::length(&tmp);
                    while(t < tmp_len + 1) {
                        if(t >= product_len) {
                            vector::push_back(&mut product, crypto_algebra::zero());
                        };

                        let a = if (t < tmp_len) {
                            vector::borrow(&tmp, t)
                        } else {
                            &crypto_algebra::zero()
                        };

                        let b = if (t == 0) {
                            &crypto_algebra::zero()
                        } else {
                            vector::borrow(&tmp, t - 1)
                        };

                        let c = vector::borrow_mut(&mut product, t);
                        *c = crypto_algebra::add(&crypto_algebra::mul(a, &crypto_algebra::mul(&crypto_algebra::neg(denom), x_k)), &crypto_algebra::mul(b, denom));

                        t = t + 1;
                    };

                    // swap tmp & product
                    let tmp2 = tmp;
                    tmp = product;
                    product = tmp2;

                    denom_idx = denom_idx + 1;
                };

                k = k + 1;
            };

            assert!(vector::length(&tmp) == vector::length(&points), 100);
            assert!(vector::length(&product) == vector::length(&points) - 1, 100);

            vector::zip_mut(&mut final_poly, &mut tmp, |final_coeff, interpolation_coeff| {
                let final_coeff: &mut Element<Fr> = final_coeff;
                let interpolation_coeff: &Element<Fr> = &*interpolation_coeff;
                *final_coeff = crypto_algebra::add(final_coeff, &crypto_algebra::mul(interpolation_coeff, eval));
            });

            j = j + 1;
        };

        final_poly
    }

    fun evaluate_vanishing_polynomial(points: vector<Element<Fr>>, z: Element<Fr>): Element<Fr> {
        vector::fold(points, crypto_algebra::one<Fr>(), |val, point| {
            crypto_algebra::mul(&crypto_algebra::sub(&z, &point), &val)
        })
    }

    fun eval_polynomial(poly: vector<Element<Fr>>, point: Element<Fr>): Element<Fr> {
        vector::foldr(poly, crypto_algebra::zero<Fr>(), |coeff, val| {
            crypto_algebra::add(&crypto_algebra::mul(&val, &point), &coeff)
        })
    }

    fun remove_duplicate_and_sort(tree: &vector<Element<Fr>>): vector<Element<Fr>> {

        if(vector::length(tree) <= 1) {
            return *tree
        };

        let btree: vector<Element<Fr>> = vector::empty();

        vector::for_each_ref(tree, |e| {
            let e: &Element<Fr> = e;
            let (find, _) = vector::find(&btree, |ref| crypto_algebra::eq(e, ref));
            if(!find) {
                vector::push_back(&mut btree, *e);
            };
        });

        let i = 0;
        let tree_len = vector::length(&btree);
        while (i < tree_len - 1) {
            let j = 0;
            while (j < tree_len - 1 - i) {
                let e_i = vector::borrow(&btree, j);
                let e_j = vector::borrow(&btree, j + 1);

                let e_i_bytes = bn254_utils::serialize_fr(e_i);
                let e_j_bytes = bn254_utils::serialize_fr(e_j);
                if(is_greater_than(&compare_u8_vector(e_i_bytes, e_j_bytes))) {
                    vector::swap(&mut btree, j, j + 1);
                };

                j = j + 1;
            };

            i = i + 1;
        };

        btree
    }

    #[test(s = @std)]
    fun test_construct_intermediate_sets(s: &signer) {
        enable_cryptography_algebra_natives(s);

        let queries: vector<VerifierQuery> = vector[
            query::new_commitment(
                option::destroy_some(bn254_utils::deserialize_g1(&x"0100000000000000000000000000000000000000000000000000000000000000")),
                option::destroy_some(bn254_utils::deserialize_fr(&x"0200000000000000000000000000000000000000000000000000000000000000")),
                option::destroy_some(bn254_utils::deserialize_fr(&x"0300000000000000000000000000000000000000000000000000000000000000")),
            ),
            query::new_commitment(
                option::destroy_some(bn254_utils::deserialize_g1(&x"0100000000000000000000000000000000000000000000000000000000000000")),
                option::destroy_some(bn254_utils::deserialize_fr(&x"0500000000000000000000000000000000000000000000000000000000000000")),
                option::destroy_some(bn254_utils::deserialize_fr(&x"0600000000000000000000000000000000000000000000000000000000000000")),
            ),
            query::new_commitment(
                option::destroy_some(bn254_utils::deserialize_g1(&x"0100000000000000000000000000000000000000000000000000000000000000")),
                option::destroy_some(bn254_utils::deserialize_fr(&x"0800000000000000000000000000000000000000000000000000000000000000")),
                option::destroy_some(bn254_utils::deserialize_fr(&x"0900000000000000000000000000000000000000000000000000000000000000")),
            )
        ];

        let (rotation_sets, super_point_set) = construct_intermediate_sets(&queries);
        assert!(vector::length(&super_point_set) == vector::length(&queries), 100);
        // Used same g1 elements
        assert!(vector::length(&rotation_sets) == 1, 100);
    }

    #[test(s = @std)]
    fun test_lagrange_interpolate(s: &signer) {
        enable_cryptography_algebra_natives(s);

        let points: vector<Element<Fr>> = vector[
            crypto_algebra::from_u64<Fr>(1),
            crypto_algebra::from_u64<Fr>(2),
            crypto_algebra::from_u64<Fr>(4),
            crypto_algebra::from_u64<Fr>(8),
        ];

        let evals: vector<Element<Fr>> = vector[
            crypto_algebra::from_u64<Fr>(10),
            crypto_algebra::from_u64<Fr>(20),
            crypto_algebra::from_u64<Fr>(40),
            crypto_algebra::from_u64<Fr>(100),
        ];

        let poly = lagrange_interpolate(points, evals);
        assert!(vector::length(&poly) == vector::length(&points), 100);

        vector::zip(points, evals, |p, eval| {
            let eval: Element<Fr> = eval;
            let eval_poly = eval_polynomial(poly, p);
            assert!(crypto_algebra::eq(&eval_poly, &eval), 100);
        });
    }
}
