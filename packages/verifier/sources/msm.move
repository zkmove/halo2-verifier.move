module halo2_verifier::msm {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};

    use aptos_std::bn254_algebra::{G1, Fr};

    struct MSM has copy, drop {
        scalars: vector<Element<Fr>>,
        bases: vector<Element<G1>>,
    }

    public fun empty_msm(): MSM {
        MSM {
            scalars: vector::empty(),
            bases: vector::empty(),
        }
    }

    public fun scale(msm: &mut MSM, factor: &Element<Fr>) {
        let length = vector::length(&msm.scalars);
        if (length > 0) {
            vector::for_each_mut(&mut msm.scalars, |p| {
                let p: &mut Element<Fr> = p;
                *p = crypto_algebra::mul(p, factor);
            });
        };
    }

    public fun append_term(msm: &mut MSM, scalar: Element<Fr>, point: Element<G1>) {
        vector::push_back(&mut msm.scalars, scalar);
        vector::push_back(&mut msm.bases, point);
    }

    public fun add_msm(msm: &mut MSM, other: &MSM) {
        vector::append(&mut msm.scalars, other.scalars);
        vector::append(&mut msm.bases, other.bases);
    }

    public fun eval(msm: &MSM): Element<G1> {
        crypto_algebra::multi_scalar_mul(&msm.bases, &msm.scalars)
    }
}
