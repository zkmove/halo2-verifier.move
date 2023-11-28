module halo2_verifier::multivariate_poly {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};
    
    use halo2_verifier::bn254_types::{Fr};
    use halo2_verifier::bn254_arithmetic;

    /// TODO: we cannot make the poly `store`, as Scalar cannot be store.
    /// it's something like: coff1 * x1^1 * x2^2 + coff2 * x2^3 * x5^4 + coff3
    struct MultiVariatePoly has drop {
        terms: vector<Term>,
    }

    /// example: coff1 * x1^1 * x2^2,
    /// then: coff = coff1, terms = [(1,1), (2,2)]
    struct Term has drop{
        coff: Element<Fr>,
        terms: vector<SparseTerm>,
    }
    /// for x2^3, sparse term is: (2, 3)
    struct SparseTerm has drop {
        variable_index: u64,
        power: u64
    }

    public fun terms(self: &MultiVariatePoly): &vector<Term> {
        &self.terms
    }
    public fun sparse_terms(term: &Term): &vector<SparseTerm> {
        &term.terms
    }
    public fun coff(term: &Term): &Element<Fr> {
        &term.coff
    }
    public fun variable_index(term: &SparseTerm): u64 {
        term.variable_index
    }
    public fun power(term: &SparseTerm): u64 {
        term.power
    }

    /// evalute the poly given access to the variable value by it's index.
    public inline fun evaluate(self: &MultiVariatePoly, var_access: |u64| &Element<Fr>): Element<Fr> {
        let i = 0;
        let terms = terms(self);
        let term_len = vector::length(terms);
        let result = crypto_algebra::zero<Fr>();
        while (i < term_len) {
            let r = eval(vector::borrow(terms, i), |i| var_access(i));
            i = i+1;
            result = crypto_algebra::add<Fr>(&result, &r);
        };
        result
    }

    inline fun eval(term: &Term, var_access: |u64| &Element<Fr>): Element<Fr> {
        let i = 0;
        let terms = sparse_terms(term);
        let term_len = vector::length(terms);
        let result = crypto_algebra::one<Fr>();
        while (i < term_len) {
            let term = vector::borrow(terms, i);
            let var: &Element<Fr> = var_access(variable_index(term));
            result = crypto_algebra::mul<Fr>(&result, &bn254_arithmetic::pow<Fr>(var, power(term)));
            i = i+1;
        };
        crypto_algebra::mul<Fr>(coff(term), &result)
    }
}