module halo2_verifier::expression {
    use std::vector;

    use aptos_std::bn254_algebra::Fr;
    use aptos_std::crypto_algebra::{Self, Element};

    use halo2_verifier::bn254_utils;
    use halo2_verifier::multivariate_poly::{Self, MultiVariatePoly, Term, SparseTerm, variable_index, power};

    struct Expression has store, drop {
        poly: MultiVariatePoly<u16>,
    }

    public fun new(poly: MultiVariatePoly<u16>): Expression {
        Expression {
            poly
        }
    }

    public fun poly(self: &Expression): &MultiVariatePoly<u16> {
        &self.poly
    }

    public fun evaluate(
        self: &Expression,
        coeffs: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>
    ): Element<Fr> {
        let advice_len = vector::length(advice_evals);
        let fixed_len = vector::length(fixed_evals);
        let instance_len = vector::length(instance_evals);
        let challenge_len = vector::length(challenges);

        let advice_range = advice_len;
        let fixed_range = advice_range + fixed_len;
        let instance_range = fixed_range + instance_len;
        let challenge_range = instance_range + challenge_len;


        multivariate_poly::evaluate(&self.poly, |term| {
            let term: &Term<u16> = term;
            let coff_index = multivariate_poly::coff(term);
            let sparse_term = multivariate_poly::sparse_terms(term);
            let coff = vector::borrow(coeffs, (*coff_index as u64));
            eval(coff, sparse_term, |idx| {
                let idx = (idx as u64);
                if (idx < advice_range) {
                    vector::borrow(advice_evals, idx)
                } else if (idx < fixed_range) {
                    vector::borrow(fixed_evals, idx - advice_range)
                } else if (idx < instance_range) {
                    vector::borrow(instance_evals, idx - fixed_range)
                } else if (idx < challenge_range) {
                    vector::borrow(challenges, idx - instance_range)
                } else {
                    abort 100
                }
            })
        }, |a, b| crypto_algebra::add(&a, &b))
    }

    inline fun eval(coeff: &Element<Fr>, terms: &vector<SparseTerm>, var_access: |u32| &Element<Fr>): Element<Fr> {
        let result = crypto_algebra::one<Fr>();
        vector::for_each_ref(terms, |term| {
            let var: &Element<Fr> = var_access(variable_index(term));
            result = crypto_algebra::mul<Fr>(&result, &bn254_utils::pow_u32<Fr>(var, power(term)));
        });
        crypto_algebra::mul<Fr>(coeff, &result)
    }
}
