module halo2_common::domain {
    use std::option;
    use std::vector;

    use aptos_std::crypto_algebra::{Self, Element};

    use aptos_std::bn254_algebra::{Fr};
    use halo2_common::i32::{Self, I32};
    use halo2_common::bn254_utils;
    use halo2_common::bn254_utils::{root_of_unity, serialize_fr};
    use std::string::String;
    use aptos_std::string_utils;

    /// TODO(optimize): we can calculate the fields offchain, and store it in protocol.
    /// so we can eliminate the computation cost of the root_of_unity.
    struct Domain has copy, drop {
        k: u8,
        j: u32,
        n: u32,
        n_inv: Element<Fr>,
        omega: Element<Fr>,
        omega_inv: Element<Fr>,
    }

    public fun new(j: u32, k: u8): Domain {
        let omega = root_of_unity(k);
        let n = 1u32 << (k);

        Domain {
            k, j,
            n,
            n_inv: option::destroy_some( crypto_algebra::inv(&crypto_algebra::from_u64((n as u64)))),
            omega_inv: option::destroy_some(crypto_algebra::inv(&omega)),
            omega
        }
    }

    public fun k(self: &Domain): u8 {
        self.k
    }

    public fun n(self: &Domain): u32 {
        self.n
    }

    public fun quotient_poly_degree(domain: &Domain): u64 {
        ((domain.j - 1) as u64)
    }

    public fun rotate_omega(domain: &Domain, x: &Element<Fr>, rotation: &I32): Element<Fr> {
        let rotation_value = i32::abs(rotation);
        // todo(optimize): we can pre-calculate some of them, and if not found, then calculate.
        let multiple = if (i32::is_neg(rotation)) {
            bn254_utils::pow_u32<Fr>(&domain.omega_inv, rotation_value)
        } else {
            bn254_utils::pow_u32<Fr>(&domain.omega, rotation_value)
        };
        crypto_algebra::mul<Fr>(x, &multiple)
    }

    /// Computes evaluations (at the point `x`, where `xn = x^n`) of Lagrange
    /// basis polynomials `l_i(X)` defined such that `l_i(omega^i) = 1` and
    /// `l_i(omega^j) = 0` for all `j != i` at each provided rotation `i`.
    public fun l_i_range(
        self: &Domain,
        x: &Element<Fr>,
        xn: &Element<Fr>,
        from: I32,
        until: I32
    ): vector<Element<Fr>> {
        // (x^n - 1)/n
        let common = crypto_algebra::mul(&self.n_inv, &crypto_algebra::sub(xn, &crypto_algebra::one()));

        let result = vector::empty();
        let cur = from;
        while (cur != until) {
            let rotation = &cur;
            // x - w^i
            let r = crypto_algebra::sub(x, &rotate_omega(self, &crypto_algebra::one<Fr>(), rotation));
            // todo(optimize): batch invert them?
            r = option::destroy_some(crypto_algebra::inv(&r));
            r = rotate_omega(self, &crypto_algebra::mul(&r, &common), rotation);
            vector::push_back(&mut result, r);
            cur = i32::add(&cur, &i32::from(1));
        };

        result
    }

    public fun format(self: &Domain): String {
        string_utils::format3(&b"domain: k {}, j {}, omega: {}", self.k, self.j, serialize_fr(&self.omega))
    }
}