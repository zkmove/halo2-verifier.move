// Copyright (c) zkMove Authors

module halo2_common::msm {
    use sui::bn254;
    use sui::group_ops::{Self, Element};
    use halo2_common::bn254_utils::eq_elements;

    const E_INVALID_INPUT: u64 = 1;
    const MAX_NATIVE_MSM_TERMS: u64 = 32;

    public struct MSM has copy, drop {
        scalars: vector<Element<bn254::Scalar>>,
        bases: vector<Element<bn254::G1>>,
    }

    public fun empty_msm(): MSM {
        MSM {
            scalars: vector[],
            bases: vector[],
        }
    }

    public fun scale(msm: &mut MSM, factor: &Element<bn254::Scalar>) {
        let mut i = 0;
        let length = msm.scalars.length();
        while (i < length) {
            let p = &mut msm.scalars[i];
            *p = bn254::scalar_mul(p, factor);
            i = i + 1;
        };
    }

    public fun append_term(
        msm: &mut MSM,
        scalar: Element<bn254::Scalar>,
        point: Element<bn254::G1>,
    ) {
        vector::push_back(&mut msm.scalars, scalar);
        vector::push_back(&mut msm.bases, point);
    }

    public fun add_msm(msm: &mut MSM, other: &MSM) {
        vector::append(&mut msm.scalars, other.scalars);
        vector::append(&mut msm.bases, other.bases);
    }

    /// Evaluates the MSM using Sui's native BN254 G1 MSM.
    ///
    /// Sui's native MSM aborts on empty input and when more than 32 terms are
    /// passed at once. This wrapper returns the G1 identity for empty MSMs,
    /// combines duplicate bases, and evaluates larger MSMs in native-sized chunks.
    public fun eval(msm: &MSM): Element<bn254::G1> {
        let length = msm.scalars.length();
        assert!(length == msm.bases.length(), E_INVALID_INPUT);

        let (scalars, bases) = combine_duplicate_bases(msm);
        eval_vectors(&scalars, &bases)
    }

    fun combine_duplicate_bases(msm: &MSM): (vector<Element<bn254::Scalar>>, vector<Element<bn254::G1>>) {
        let mut scalars = vector[];
        let mut bases = vector[];
        let zero = bn254::scalar_zero();
        let mut i = 0;
        while (i < msm.scalars.length()) {
            let scalar = msm.scalars[i];
            if (!group_ops::equal(&scalar, &zero)) {
                let base = msm.bases[i];
                let mut found = false;
                let mut j = 0;
                while (j < bases.length()) {
                    if (group_ops::equal(&bases[j], &base)) {
                        let value = &mut scalars[j];
                        *value = bn254::scalar_add(value, &scalar);
                        found = true;
                        j = bases.length();
                    } else {
                        j = j + 1;
                    };
                };

                if (!found) {
                    scalars.push_back(scalar);
                    bases.push_back(base);
                };
            };
            i = i + 1;
        };
        (scalars, bases)
    }

    fun eval_vectors(
        scalars: &vector<Element<bn254::Scalar>>,
        bases: &vector<Element<bn254::G1>>,
    ): Element<bn254::G1> {
        let length = scalars.length();
        if (length == 0) {
            return bn254::g1_identity()
        };

        let mut result = bn254::g1_identity();
        let mut i = 0;
        while (i < length) {
            let end = if (i + MAX_NATIVE_MSM_TERMS < length) {
                i + MAX_NATIVE_MSM_TERMS
            } else {
                length
            };
            let mut chunk_scalars = vector[];
            let mut chunk_bases = vector[];
            while (i < end) {
                chunk_scalars.push_back(scalars[i]);
                chunk_bases.push_back(bases[i]);
                i = i + 1;
            };

            result = bn254::g1_add(&result, &bn254::g1_multi_scalar_multiplication(&chunk_scalars, &chunk_bases));
        };

        result
    }

    public fun eq(msm: &MSM, other: &MSM): bool {
        eq_elements<bn254::Scalar>(&msm.scalars, &other.scalars)
            && eq_elements<bn254::G1>(&msm.bases, &other.bases)
    }
}
