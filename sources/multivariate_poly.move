module halo2_verifier::multivariate_poly {
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};

    use aptos_std::bn254_algebra::{Fr};
    use halo2_verifier::bn254_utils;

    use std::string::String;

    use std::string;

    use aptos_std::string_utils;

    use std::bn254_algebra::FormatFrMsb;

    /// TODO: we cannot make the poly `store`, as Scalar cannot be store.
    /// it's something like: coff1 * x1^1 * x2^2 + coff2 * x2^3 * x5^4 + coff3
    struct MultiVariatePoly has  drop {
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
        variable_index: u32,
        power: u32
    }

    public fun new_poly(terms: vector<Term>): MultiVariatePoly {
        MultiVariatePoly {
            terms
        }
    }
    public fun terms(self: &MultiVariatePoly): &vector<Term> {
        &self.terms
    }

    public fun new_term(coff: Element<Fr>, terms: vector<SparseTerm>): Term {
        Term {
            coff,
            terms
        }
    }
    public fun coff(term: &Term): &Element<Fr> {
        &term.coff
    }
    public fun sparse_terms(term: &Term): &vector<SparseTerm> {
        &term.terms
    }

    public fun new_sparse_term(variable_index: u32, power: u32): SparseTerm {
        SparseTerm {
            variable_index,
            power
        }
    }
    public fun variable_index(term: &SparseTerm): u32 {
        term.variable_index
    }
    public fun power(term: &SparseTerm): u32 {
        term.power
    }

    /// evalute the poly given access to the variable value by it's index.
    public inline fun evaluate(self: &MultiVariatePoly, var_access: |u32| &Element<Fr>): Element<Fr> {
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

    inline fun eval(term: &Term, var_access: |u32| &Element<Fr>): Element<Fr> {
        let i = 0;
        let terms = sparse_terms(term);
        let term_len = vector::length(terms);
        let result = crypto_algebra::one<Fr>();
        while (i < term_len) {
            let term = vector::borrow(terms, i);
            let var: &Element<Fr> = var_access(variable_index(term));
            result = crypto_algebra::mul<Fr>(&result, &bn254_utils::pow_u32<Fr>(var, power(term)));
            i = i+1;
        };
        crypto_algebra::mul<Fr>(coff(term), &result)
    }


    public fun format(self: &MultiVariatePoly): vector<String> {
        vector::map_ref(&self.terms, |term| {
            let t: &Term = term;
             format_term(t)
        })
    }


    fun format_term(self: &Term):String {
        let result = string::utf8(b"");
        string::append(&mut result, string_utils::to_string(&crypto_algebra::serialize<Fr, FormatFrMsb>(&self.coff)));
        vector::for_each_ref(&self.terms, |term| {
            let t: &SparseTerm = term;
            if (t.power == 1) {
                string::append(&mut result, string_utils::format1(&b" * x_{}", t.variable_index));
            } else {
                string::append(&mut result, string_utils::format2(&b" * x_{}^{}", t.variable_index, t.power));
            }
        });
        result
    }
}