// Copyright (c) zkMove Authors

module halo2_common::msm {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils::eq_elements;

    const E_INVALID_INPUT: u64 = 1;

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
    /// Sui's native MSM aborts on empty input, so this wrapper returns the G1
    /// identity for empty MSMs. The underlying fastcrypto implementation now
    /// accepts arbitrary input lengths, so non-empty MSMs can be evaluated in a
    /// single native call without chunking or duplicate-base pre-processing.
    public fun eval(msm: &MSM): Element<bn254::G1> {
        let length = msm.scalars.length();
        assert!(length == msm.bases.length(), E_INVALID_INPUT);

        eval_vectors(&msm.scalars, &msm.bases)
    }

    fun eval_vectors(
        scalars: &vector<Element<bn254::Scalar>>,
        bases: &vector<Element<bn254::G1>>,
    ): Element<bn254::G1> {
        if (scalars.length() == 0) {
            return bn254::g1_identity()
        };

        bn254::g1_multi_scalar_multiplication(scalars, bases)
    }

    public fun eq(msm: &MSM, other: &MSM): bool {
        eq_elements<bn254::Scalar>(&msm.scalars, &other.scalars)
            && eq_elements<bn254::G1>(&msm.bases, &other.bases)
    }
}
