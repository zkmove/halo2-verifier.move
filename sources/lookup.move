module halo2_verifier::lookup {
    use std::vector::{Self, for_each_ref};

    use halo2_verifier::bn254_types::G1;
    use halo2_verifier::domain;
    use halo2_verifier::point::Point;
    use halo2_verifier::protocol::{Self, Protocol};
    use halo2_verifier::query::{Self, VerifierQuery};
    use halo2_verifier::rotation;
    use halo2_verifier::scalar::Scalar;
    use halo2_verifier::transcript::{Self, Transcript};

    struct PermutationCommitments has copy, drop {
        permuted_input_commitment: Point<G1>,
        permuted_table_commitment: Point<G1>,
    }

    struct Commited has copy, drop {
        permuted: PermutationCommitments,
        product_commitment: Point<G1>,
    }

    struct Evaluated has  drop {
        commited: Commited,
        product_eval: Scalar,
        product_next_eval: Scalar,
        permuted_input_eval: Scalar,
        permuted_input_inv_eval: Scalar,
        permuted_table_eval: Scalar,
    }

    public fun read_permuted_commitments(transcript: &mut Transcript): PermutationCommitments {
        PermutationCommitments {
            permuted_input_commitment: transcript::read_point(transcript),
            permuted_table_commitment: transcript::read_point(transcript),
        }
    }

    public fun read_product_commitment(c: PermutationCommitments, transcript: &mut Transcript): Commited {
        Commited {
            permuted: c,
            product_commitment: transcript::read_point(transcript),
        }
    }

    public fun evaluate(c: &Commited, transcript: &mut Transcript): Evaluated {
        let product_eval = transcript::read_scalar(transcript);
        let product_next_eval = transcript::read_scalar(transcript);
        let permuted_input_eval = transcript::read_scalar(transcript);
        let permuted_input_inv_eval = transcript::read_scalar(transcript);
        let permuted_table_eval = transcript::read_scalar(transcript);
        Evaluated {
            commited: *c,
            product_eval,
            product_next_eval,
            permuted_input_eval,
            permuted_input_inv_eval,
            permuted_table_eval
        }
    }

    public fun queries(self: &vector<Evaluated>, queries: &mut vector<VerifierQuery>, protocol: &Protocol, x: &Scalar) {
        let domain = protocol::domain(protocol);
        let x_inv = domain::rotate_omega(domain, x, &rotation::prev(1));
        let x_next = domain::rotate_omega(domain, x, &rotation::next(1));
        for_each_ref(self, |evaluated| {
            let eval: &Evaluated = evaluated;
            // Open lookup product commitment at x
            vector::push_back(queries, query::new_commitment(eval.commited.product_commitment, *x, eval.product_eval));
            // Open lookup input commitments at x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.permuted.permuted_input_commitment, *x, eval.permuted_input_eval)
            );
            // Open lookup table commitments at x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.permuted.permuted_table_commitment, *x, eval.permuted_table_eval)
            );
            // Open lookup input commitments at \omega^{-1} x
            vector::push_back(
                queries,
                query::new_commitment(
                    eval.commited.permuted.permuted_input_commitment,
                    x_inv,
                    eval.permuted_input_inv_eval
                )
            );
            // Open lookup product commitment at \omega x
            vector::push_back(
                queries,
                query::new_commitment(eval.commited.product_commitment, x_next, eval.product_next_eval)
            );
        });
    }
}
