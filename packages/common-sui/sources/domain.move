// Copyright (c) zkMove Authors

module halo2_common::domain {
    use sui::bn254;
    use sui::group_ops::Element;
    use halo2_common::bn254_utils::{pow_u32, root_of_unity};
    use halo2_common::i32::{Self, I32};

    /// Evaluation domain metadata used by the Halo2 verifier.
    public struct Domain has copy, drop {
        k: u8,
        j: u32,
        n: u32,
        n_inv: Element<bn254::Scalar>,
        omega: Element<bn254::Scalar>,
        omega_inv: Element<bn254::Scalar>,
    }

    public fun new(j: u32, k: u8): Domain {
        let omega = root_of_unity(k);
        let n = 1u32 << k;
        Domain {
            k,
            j,
            n,
            n_inv: bn254::scalar_inv(&bn254::scalar_from_u64((n as u64))),
            omega_inv: bn254::scalar_inv(&omega),
            omega,
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

    public fun rotate_omega(
        domain: &Domain,
        x: &Element<bn254::Scalar>,
        rotation: &I32,
    ): Element<bn254::Scalar> {
        let rotation_value = i32::abs(rotation);
        let multiple = if (i32::is_neg(rotation)) {
            pow_u32(&domain.omega_inv, rotation_value)
        } else {
            pow_u32(&domain.omega, rotation_value)
        };
        bn254::scalar_mul(x, &multiple)
    }

    /// Computes evaluations of Lagrange basis polynomials `l_i(X)` at `x` for
    /// rotations in `[from, until)`.
    public fun l_i_range(
        self: &Domain,
        x: &Element<bn254::Scalar>,
        xn: &Element<bn254::Scalar>,
        from: I32,
        until: I32,
    ): vector<Element<bn254::Scalar>> {
        let common = bn254::scalar_mul(
            &self.n_inv,
            &bn254::scalar_sub(xn, &bn254::scalar_one()),
        );

        let mut result = vector[];
        let mut cur = from;
        while (cur != until) {
            let rotation = &cur;
            let denominator = bn254::scalar_sub(
                x,
                &rotate_omega(self, &bn254::scalar_one(), rotation),
            );
            let denominator_inv = bn254::scalar_inv(&denominator);
            let value = rotate_omega(
                self,
                &bn254::scalar_mul(&denominator_inv, &common),
                rotation,
            );
            vector::push_back(&mut result, value);
            cur = i32::add(&cur, &i32::from(1));
        };

        result
    }
}
