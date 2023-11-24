module halo2_verifier::multivariate_poly {
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::scalar;
    use std::vector;

    /// TODO: we cannot make the poly `store`, as Scalar cannot be store.
    /// it's something like: coff1 * x1^1 * x2^2 + coff2 * x2^3 * x5^4 + coff3
    struct MultiVariatePoly has drop {
        terms: vector<Term>,
    }

    /// example: coff1 * x1^1 * x2^2,
    /// then: coff = coff1, terms = [(1,1), (2,2)]
    struct Term has drop{
        coff: Scalar,
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
    public fun coff(term: &Term): &Scalar {
        &term.coff
    }
    public fun variable_index(term: &SparseTerm): u64 {
        term.variable_index
    }
    public fun power(term: &SparseTerm): u64 {
        term.power
    }

    /// evalute the poly given access to the variable value by it's index.
    public inline fun evaluate(self: &MultiVariatePoly, var_access: |u64| &Scalar): Scalar {
        let i = 0;
        let terms = terms(self);
        let term_len = vector::length(terms);
        let result = scalar::zero();
        while (i < term_len) {
            let r = eval(vector::borrow(terms, i), |i| var_access(i));
            i = i+1;
            result = scalar::add(&result, &r);
        };
        result
    }

    inline fun eval(term: &Term, var_access: |u64| &Scalar): Scalar {
        let i = 0;
        let terms = sparse_terms(term);
        let term_len = vector::length(terms);
        let result = scalar::one();
        while (i < term_len) {
            let term = vector::borrow(terms, i);
            let var: &Scalar = var_access(variable_index(term));
            result = scalar::mul(&result, &scalar::from_element(scalar::pow(scalar::inner(var), power(term))));
            i = i+1;
        };
        scalar::mul(coff(term), &result)
    }
}