module halo2_verifier::msm {
    use std::vector;

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::point::{Self, Point};
    use halo2_verifier::scalar::{Self, Scalar};

    struct MSM has copy, drop {
        scalars: vector<Scalar>,
        bases: vector<Point<G1>>,
    }

    public fun empty_msm(): MSM {
        MSM {
            scalars: vector::empty(),
            bases: vector::empty(),
        }
    }

    public fun scale(msm: &mut MSM, factor: &Scalar) {
        let length = vector::length(&msm.scalars);
        if (length > 0) {
            vector::for_each_mut(&mut msm.scalars, |p| {
                let p: &mut Scalar = p;
                *p = scalar::mul(p, factor);
            });
        };
    }

    public fun append_term(msm: &mut MSM, scalar: Scalar, point: Point<G1>) {
        vector::push_back(&mut msm.scalars, scalar);
        vector::push_back(&mut msm.bases, point);
    }

    public fun add_msm(msm: &mut MSM, other: &MSM) {
        vector::append(&mut msm.scalars, other.scalars);
        vector::append(&mut msm.bases, other.bases);
    }

    public fun eval(msm: &MSM): Point<G1> {
        point::multi_scalar_mul(&msm.bases, &msm.scalars)
    }

    public fun eval(msm: &MSM): Point<G1> {
        abort 100
    }
}
