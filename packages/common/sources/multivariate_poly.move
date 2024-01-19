module halo2_common::multivariate_poly {
    use std::vector;

    #[test_only]
    use aptos_std::string_utils;
    #[test_only]
    use std::string::{Self, String};

    /// it's something like: coff1 * x1^1 * x2^2 + coff2 * x2^3 * x5^4 + coff3
    struct MultiVariatePoly<C> has store, drop {
        terms: vector<Term<C>>,
    }

    /// example: coff1 * x1^1 * x2^2,
    /// then: coff = coff1, terms = [(1,1), (2,2)]
    struct Term<C> has store, drop {
        coff: C,
        terms: vector<SparseTerm>,
    }

    /// for x2^3, sparse term is: (2, 3)
    struct SparseTerm has store,copy, drop {
        variable_index: u32,
        power: u32
    }

    public fun new_poly<C>(terms: vector<Term<C>>): MultiVariatePoly<C> {
        MultiVariatePoly {
            terms
        }
    }

    public fun terms<C>(self: &MultiVariatePoly<C>): &vector<Term<C>> {
        &self.terms
    }

    public fun new_term<C>(coff: C, terms: vector<SparseTerm>): Term<C> {
        Term {
            coff,
            terms
        }
    }

    public fun coff<C>(term: &Term<C>): &C {
        &term.coff
    }

    public fun sparse_terms<C>(term: &Term<C>): &vector<SparseTerm> {
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
    public inline fun evaluate<C, R>(self: &MultiVariatePoly<C>, term_eval: |&Term<C>| R, term_add: |R, R| R): R {
        let terms = terms(self);
        let term_len = vector::length(terms);
        let result = term_eval(vector::borrow(terms, 0));
        let i = 1;
        while (i < term_len) {
            let r = term_eval(vector::borrow(terms, i));
            i = i + 1;
            result = term_add(result, r);
        };
        result
    }


    #[test_only]
    public fun format<C: drop>(self: &MultiVariatePoly<C>): vector<String> {
        vector::map_ref(&self.terms, |term| {
            let t: &Term<C> = term;
            format_term(t)
        })
    }

    #[test_only]
    fun format_term<C: drop>(self: &Term<C>): String {
        let result = string::utf8(b"");
        string::append(&mut result, string_utils::to_string(&self.coff));
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