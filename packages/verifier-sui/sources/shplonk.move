// Copyright (c) zkMove Authors

module halo2_verifier::shplonk {
    use sui::bn254;
    use sui::group_ops::{Self, Element};
    use halo2_common::bn254_utils;
    use halo2_common::msm;
    use halo2_common::params::{Self, Params};
    use halo2_common::query::{Self, CommitmentReference, VerifierQuery};
    use halo2_verifier::transcript::{Self, Transcript};

    public struct CommitmentRotationSet has copy, drop {
        rotations: vector<Element<bn254::Scalar>>,
        commitment: CommitmentReference,
    }

    public struct RotationSetCommitment has copy, drop {
        rotations: vector<Element<bn254::Scalar>>,
        commitments: vector<CommitmentReference>,
    }

    public struct Commitment has copy, drop {
        commitment: CommitmentReference,
        evals: vector<Element<bn254::Scalar>>,
    }

    public struct RotationSet has copy, drop {
        points: vector<Element<bn254::Scalar>>,
        commitments: vector<Commitment>,
    }

    public fun verify(
        params: &Params,
        transcript: &mut Transcript,
        queries: &vector<VerifierQuery>,
    ): bool {
        let (rotation_sets, super_point_set) = construct_intermediate_sets(queries);

        let y = transcript::squeeze_challenge(transcript);
        let v = transcript::squeeze_challenge(transcript);

        let h1 = transcript::read_point(transcript);
        let u = transcript::squeeze_challenge(transcript);
        let h2 = transcript::read_point(transcript);

        let mut z_0_diff_inverse = bn254::scalar_zero();
        let mut z_0 = bn254::scalar_zero();
        let mut outer_msm = msm::empty_msm();
        let mut r_outer_acc = bn254::scalar_zero();
        let mut power_of_v = bn254::scalar_one();

        let mut i = 0;
        while (i < rotation_sets.length()) {
            let rotation_set = &rotation_sets[i];
            let mut diffs = vector[];
            let mut j = 0;
            while (j < super_point_set.length()) {
                let point = super_point_set[j];
                if (!contains_scalar(&rotation_set.points, &point)) {
                    vector::push_back(&mut diffs, point);
                };
                j = j + 1;
            };

            let mut z_diff_i = evaluate_vanishing_polynomial(diffs, u);
            if (i == 0) {
                z_0 = evaluate_vanishing_polynomial(rotation_set.points, u);
                z_0_diff_inverse = bn254_utils::invert(&z_diff_i);
                z_diff_i = bn254::scalar_one();
            } else {
                z_diff_i = bn254::scalar_mul(&z_diff_i, &z_0_diff_inverse);
            };

            let mut inner_msm = msm::empty_msm();
            let mut r_inner_acc = bn254::scalar_zero();
            let mut power_of_y = bn254::scalar_one();

            let mut j = 0;
            while (j < rotation_set.commitments.length()) {
                let commitment_data = &rotation_set.commitments[j];
                let r_x = lagrange_interpolate(rotation_set.points, commitment_data.evals);
                let r_eval = bn254::scalar_mul(&power_of_y, &eval_polynomial(r_x, u));
                r_inner_acc = bn254::scalar_add(&r_inner_acc, &r_eval);

                let c = query::multiply(&commitment_data.commitment, &power_of_y);
                msm::add_msm(&mut inner_msm, &c);

                power_of_y = bn254::scalar_mul(&power_of_y, &y);
                j = j + 1;
            };

            let scale = bn254::scalar_mul(&power_of_v, &z_diff_i);
            msm::scale(&mut inner_msm, &scale);
            msm::add_msm(&mut outer_msm, &inner_msm);
            r_outer_acc = bn254::scalar_add(
                &r_outer_acc,
                &bn254::scalar_mul(&power_of_v, &bn254::scalar_mul(&r_inner_acc, &z_diff_i)),
            );

            power_of_v = bn254::scalar_mul(&power_of_v, &v);
            i = i + 1;
        };

        msm::append_term(&mut outer_msm, bn254::scalar_neg(&r_outer_acc), *params::g(params));
        msm::append_term(&mut outer_msm, bn254::scalar_neg(&z_0), h1);
        msm::append_term(&mut outer_msm, u, h2);
        let right = msm::eval(&outer_msm);

        let pairing_result = bn254::gt_add(
            &bn254::pairing(&h2, params::s_g2(params)),
            &bn254::pairing(&right, &bn254::g2_neg(params::g2(params))),
        );
        group_ops::equal(&pairing_result, &bn254::gt_identity())
    }

    fun construct_intermediate_sets(
        queries: &vector<VerifierQuery>,
    ): (vector<RotationSet>, vector<Element<bn254::Scalar>>) {
        let mut super_point_set = vector[];
        let mut commitment_rotation_set_map: vector<CommitmentRotationSet> = vector[];

        let mut i = 0;
        while (i < queries.length()) {
            let q = queries[i];
            let point = *query::point(&q);
            let commitment = *query::commitment(&q);
            vector::push_back(&mut super_point_set, point);

            let (find, index) = find_commitment_rotation_set(&commitment_rotation_set_map, &commitment);
            if (find) {
                vector::push_back(&mut commitment_rotation_set_map[index].rotations, point);
            } else {
                vector::push_back(&mut commitment_rotation_set_map, CommitmentRotationSet {
                    rotations: vector[point],
                    commitment,
                });
            };
            i = i + 1;
        };

        let mut i = 0;
        while (i < commitment_rotation_set_map.length()) {
            let rotations = remove_duplicate_and_sort(&commitment_rotation_set_map[i].rotations);
            commitment_rotation_set_map[i].rotations = rotations;
            i = i + 1;
        };

        let mut rotation_set_commitment_map: vector<RotationSetCommitment> = vector[];
        let mut i = 0;
        while (i < commitment_rotation_set_map.length()) {
            let c = &commitment_rotation_set_map[i];
            let (find, index) = find_rotation_set_commitment(&rotation_set_commitment_map, &c.rotations);
            if (find) {
                vector::push_back(&mut rotation_set_commitment_map[index].commitments, c.commitment);
            } else {
                vector::push_back(&mut rotation_set_commitment_map, RotationSetCommitment {
                    rotations: c.rotations,
                    commitments: vector[c.commitment],
                });
            };
            i = i + 1;
        };

        let mut rotation_sets = vector[];
        let mut i = 0;
        while (i < rotation_set_commitment_map.length()) {
            let rotation_set = &rotation_set_commitment_map[i];
            let rotations = rotation_set.rotations;
            let mut commitments = vector[];
            let mut j = 0;
            while (j < rotation_set.commitments.length()) {
                let commitment = rotation_set.commitments[j];
                let mut evals = vector[];
                let mut k = 0;
                while (k < rotations.length()) {
                    let rotation = rotations[k];
                    let query_index = find_query(queries, &commitment, &rotation);
                    vector::push_back(&mut evals, *query::eval(&queries[query_index]));
                    k = k + 1;
                };
                vector::push_back(&mut commitments, Commitment { commitment, evals });
                j = j + 1;
            };
            vector::push_back(&mut rotation_sets, RotationSet { commitments, points: rotations });
            i = i + 1;
        };

        super_point_set = remove_duplicate_and_sort(&super_point_set);
        (rotation_sets, super_point_set)
    }

    fun lagrange_interpolate(
        points: vector<Element<bn254::Scalar>>,
        evals: vector<Element<bn254::Scalar>>,
    ): vector<Element<bn254::Scalar>> {
        let points_len = points.length();
        assert!(points_len == evals.length(), 100);
        if (points_len == 1) {
            return vector[evals[0]]
        };

        let mut final_poly = repeat_zero(points_len);
        let mut j = 0;
        while (j < points_len) {
            let mut basis = vector[bn254::scalar_one()];
            let mut k = 0;
            while (k < points_len) {
                if (k != j) {
                    let alpha = bn254_utils::invert(&bn254::scalar_sub(&points[j], &points[k]));
                    let beta = bn254::scalar_neg(&bn254::scalar_mul(&alpha, &points[k]));
                    basis = multiply_linear(&basis, &beta, &alpha);
                };
                k = k + 1;
            };

            let mut i = 0;
            while (i < final_poly.length()) {
                let next = bn254::scalar_add(&final_poly[i], &bn254::scalar_mul(&basis[i], &evals[j]));
                *vector::borrow_mut(&mut final_poly, i) = next;
                i = i + 1;
            };
            j = j + 1;
        };
        final_poly
    }

    fun evaluate_vanishing_polynomial(
        points: vector<Element<bn254::Scalar>>,
        z: Element<bn254::Scalar>,
    ): Element<bn254::Scalar> {
        let mut value = bn254::scalar_one();
        let mut i = 0;
        while (i < points.length()) {
            value = bn254::scalar_mul(&bn254::scalar_sub(&z, &points[i]), &value);
            i = i + 1;
        };
        value
    }

    fun eval_polynomial(
        poly: vector<Element<bn254::Scalar>>,
        point: Element<bn254::Scalar>,
    ): Element<bn254::Scalar> {
        let mut value = bn254::scalar_zero();
        let mut i = poly.length();
        while (i > 0) {
            i = i - 1;
            value = bn254::scalar_add(&bn254::scalar_mul(&value, &point), &poly[i]);
        };
        value
    }

    fun remove_duplicate_and_sort(tree: &vector<Element<bn254::Scalar>>): vector<Element<bn254::Scalar>> {
        let mut btree = vector[];
        let mut i = 0;
        while (i < tree.length()) {
            let e = tree[i];
            if (!contains_scalar(&btree, &e)) {
                vector::push_back(&mut btree, e);
            };
            i = i + 1;
        };

        let len = btree.length();
        let mut i = 0;
        while (i < len) {
            let mut j = 0;
            while (j + 1 < len - i) {
                if (scalar_bytes_greater(&btree[j], &btree[j + 1])) {
                    vector::swap(&mut btree, j, j + 1);
                };
                j = j + 1;
            };
            i = i + 1;
        };
        btree
    }

    fun multiply_linear(
        poly: &vector<Element<bn254::Scalar>>,
        constant: &Element<bn254::Scalar>,
        linear: &Element<bn254::Scalar>,
    ): vector<Element<bn254::Scalar>> {
        let mut result = repeat_zero(poly.length() + 1);
        let mut i = 0;
        while (i < poly.length()) {
            let next_constant = bn254::scalar_add(&result[i], &bn254::scalar_mul(&poly[i], constant));
            *vector::borrow_mut(&mut result, i) = next_constant;

            let next_linear = bn254::scalar_add(&result[i + 1], &bn254::scalar_mul(&poly[i], linear));
            *vector::borrow_mut(&mut result, i + 1) = next_linear;
            i = i + 1;
        };
        result
    }

    fun repeat_zero(len: u64): vector<Element<bn254::Scalar>> {
        let mut result = vector[];
        let mut i = 0;
        while (i < len) {
            vector::push_back(&mut result, bn254::scalar_zero());
            i = i + 1;
        };
        result
    }

    fun contains_scalar(values: &vector<Element<bn254::Scalar>>, value: &Element<bn254::Scalar>): bool {
        let mut i = 0;
        while (i < values.length()) {
            if (group_ops::equal(&values[i], value)) {
                return true
            };
            i = i + 1;
        };
        false
    }

    fun find_commitment_rotation_set(
        sets: &vector<CommitmentRotationSet>,
        commitment: &CommitmentReference,
    ): (bool, u64) {
        let mut i = 0;
        while (i < sets.length()) {
            if (query::eq_commit_reference(&sets[i].commitment, commitment)) {
                return (true, i)
            };
            i = i + 1;
        };
        (false, 0)
    }

    fun find_rotation_set_commitment(
        sets: &vector<RotationSetCommitment>,
        rotations: &vector<Element<bn254::Scalar>>,
    ): (bool, u64) {
        let mut i = 0;
        while (i < sets.length()) {
            if (bn254_utils::eq_elements<bn254::Scalar>(&sets[i].rotations, rotations)) {
                return (true, i)
            };
            i = i + 1;
        };
        (false, 0)
    }

    fun find_query(
        queries: &vector<VerifierQuery>,
        commitment: &CommitmentReference,
        rotation: &Element<bn254::Scalar>,
    ): u64 {
        let mut i = 0;
        while (i < queries.length()) {
            let q = &queries[i];
            if (query::eq_commit_reference(commitment, query::commitment(q)) && group_ops::equal(rotation, query::point(q))) {
                return i
            };
            i = i + 1;
        };
        abort 101
    }

    fun scalar_bytes_greater(a: &Element<bn254::Scalar>, b: &Element<bn254::Scalar>): bool {
        let a_bytes = bn254_utils::serialize_fr(a);
        let b_bytes = bn254_utils::serialize_fr(b);
        let mut i = 0;
        while (i < a_bytes.length() && i < b_bytes.length()) {
            if (a_bytes[i] > b_bytes[i]) {
                return true
            };
            if (a_bytes[i] < b_bytes[i]) {
                return false
            };
            i = i + 1;
        };
        a_bytes.length() > b_bytes.length()
    }
}
