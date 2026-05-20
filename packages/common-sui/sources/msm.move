// Copyright (c) zkMove Authors

module halo2_common::msm {
    use sui::bn254;
    use sui::group_ops::{Element};
    use halo2_common::bn254_utils::eq_elements;

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
    /// Sui aborts if the input is empty, if lengths differ, or if the native
    /// input length limit is exceeded.
    public fun eval(msm: &MSM): Element<bn254::G1> {
        bn254::g1_multi_scalar_multiplication(&msm.scalars, &msm.bases)
    }

    public fun eq(msm: &MSM, other: &MSM): bool {
        eq_elements<bn254::Scalar>(&msm.scalars, &other.scalars)
            && eq_elements<bn254::G1>(&msm.bases, &other.bases)
    }
}
