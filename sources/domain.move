module halo2_verifier::domain {
    use std::option;
    use std::vector;

    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_types::{Fr, root_of_unity};
    use halo2_verifier::rotation::{Self, Rotation};
    use halo2_verifier::scalar::{Self, Scalar, inner};

    struct Domain has copy, drop {
        k: u32,
        j: u32,
        n: u64,
        n_inv: Element<Fr>,
        omega: Element<Fr>,
        omega_inv: Element<Fr>,
    }

    public fun new(j: u32, k: u32): Domain {
        let omega = root_of_unity(k);
        let n = 1u64 << (k as u8);

        Domain {
            k, j,
            n,
            n_inv: crypto_algebra::from_u64(n),
            omega_inv: option::destroy_some(crypto_algebra::inv(&omega)),
            omega
        }
    }

    public fun k(self: &Domain): u32 {
        self.k
    }

    public fun n(self: &Domain): u64 {
        self.n
    }

    public fun quotient_poly_degree(domain: &Domain): u64 {
        ((domain.j - 1) as u64)
    }

    public fun rotate_omega(domain: &Domain, x: &Scalar, rotation: &Rotation): Scalar {
        let rotation_value = rotation::value(rotation);
        // todo(optimize): we can pre-calculate some of them, and if not found, then calculate.
        let multiple = if (rotation::is_neg(rotation)) {
            scalar::pow(&domain.omega_inv, (rotation_value as u64))
        } else {
            scalar::pow(&domain.omega, (rotation_value as u64))
        };
        scalar::from_element(crypto_algebra::mul(scalar::inner(x), &multiple))
    }

    /// Computes evaluations (at the point `x`, where `xn = x^n`) of Lagrange
    /// basis polynomials `l_i(X)` defined such that `l_i(omega^i) = 1` and
    /// `l_i(omega^j) = 0` for all `j != i` at each provided rotation `i`.
    public fun l_i_range(
        self: &Domain,
        x: &Element<Fr>,
        xn: &Element<Fr>,
        from: Rotation,
        until: Rotation
    ): vector<Element<Fr>> {
        // (x^n - 1)/n
        let common = crypto_algebra::mul(&self.n_inv, &crypto_algebra::sub(xn, &crypto_algebra::one()));

        let result = vector::empty();
        let cur = from;
        while (cur != until) {
            let rotation = &cur;
            // x - w^i
            let r = crypto_algebra::sub(x, inner(&rotate_omega(self, &scalar::one(), rotation)));
            // todo(optimize): batch invert them?
            r = option::destroy_some(crypto_algebra::inv(&r));
            r = *inner(&rotate_omega(self, &scalar::from_element(crypto_algebra::mul(&r, &common)), rotation));
            vector::push_back(&mut result, r);
            cur = rotation::get_next(&cur);
        };

        result
    }
}