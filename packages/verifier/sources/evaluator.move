module halo2_verifier::evaluator {
    use std::vector;
    use aptos_std::bn254_algebra::Fr;
    use aptos_std::crypto_algebra::{Self, Element};

    // Error codes
    const E_INVALID_POS: u64 = 100;
    const E_INVALID_BYTES_LENGTH: u64 = 101;
    const E_INVALID_FIELD_INDEX: u64 = 102;
    const E_INVALID_FIXED_INDEX: u64 = 103;
    const E_INVALID_ADVICE_INDEX: u64 = 104;
    const E_INVALID_INSTANCE_INDEX: u64 = 105;
    const E_INVALID_CHALLENGE_INDEX: u64 = 106;
    const E_INVALID_NODE_TYPE: u64 = 107;
    const E_INVALID_INPUT_LENGTH: u64 = 108;

    // Evaluats all expressions in a serialized expressions
    public fun evaluate_exprs(
        exprs_bytes: &vector<u8>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        fields_pool: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>,
    ): vector<Element<Fr>> {
        let use_u8_index_for_fields = (use_u8_fields == 0);
        let use_u8_index_for_query = (use_u8_queries == 0);

        let pos = 0;
        let results = vector::empty<Element<Fr>>();
        while (pos < vector::length(exprs_bytes)) {
            let result = evaluate_expression(
                exprs_bytes,
                &mut pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            vector::push_back(&mut results, result);
        };
        results
    }

    // Evaluates a single serialized expression
    public fun evaluate_expression(
        expr_bytes: &vector<u8>,
        pos: &mut u64,
        fields_pool: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>,
        use_u8_index_for_fields: bool,
        use_u8_index_for_query: bool,
    ): Element<Fr> {
        assert!(*pos < vector::length(expr_bytes), E_INVALID_POS);
        let node_type = *vector::borrow(expr_bytes, *pos);
        *pos = *pos + 1;

        if (node_type == 0x00) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_fields);
            assert!(index < vector::length(fields_pool), E_INVALID_FIELD_INDEX);
            let field = *vector::borrow(fields_pool, index);
            return field
        } else if (node_type == 0x02) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_query);
            assert!(index < vector::length(fixed_evals), E_INVALID_FIXED_INDEX);
            return *vector::borrow(fixed_evals, index)
        } else if (node_type == 0x03) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_query);
            assert!(index < vector::length(advice_evals), E_INVALID_ADVICE_INDEX);
            return *vector::borrow(advice_evals, index)
        } else if (node_type == 0x04) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_query);
            assert!(index < vector::length(instance_evals), E_INVALID_INSTANCE_INDEX);
            return *vector::borrow(instance_evals, index)
        } else if (node_type == 0x05) {
            let index = deserialize_u32(expr_bytes, pos);
            assert!((index as u64) < vector::length(challenges), E_INVALID_CHALLENGE_INDEX);
            return *vector::borrow(challenges, (index as u64))
        } else if (node_type == 0x06) {
            let value = evaluate_expression(
                expr_bytes,
                pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            return crypto_algebra::neg(&value)
        } else if (node_type == 0x07) {
            let a = evaluate_expression(
                expr_bytes,
                pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            let b = evaluate_expression(
                expr_bytes,
                pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            return crypto_algebra::add<Fr>(&a, &b)
        } else if (node_type == 0x08) {
            let a = evaluate_expression(
                expr_bytes,
                pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            let b = evaluate_expression(
                expr_bytes,
                pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            return crypto_algebra::mul<Fr>(&a, &b)
        } else if (node_type == 0x09) {
            let value = evaluate_expression(
                expr_bytes,
                pos,
                fields_pool,
                advice_evals,
                fixed_evals,
                instance_evals,
                challenges,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            );
            let index = read_index(expr_bytes, pos, use_u8_index_for_fields);
            assert!(index < vector::length(fields_pool), E_INVALID_FIELD_INDEX);
            let scalar = vector::borrow(fields_pool, index);
            return crypto_algebra::mul<Fr>(&value, scalar)
        };
        abort E_INVALID_NODE_TYPE
    }

    fun read_index(expr_bytes: &vector<u8>, pos: &mut u64, use_u8: bool): u64 {
        if (use_u8) {
            assert!(*pos < vector::length(expr_bytes), E_INVALID_POS);
            let idx = ((*vector::borrow(expr_bytes, *pos)) as u64);
            *pos = *pos + 1;
            idx
        } else {
            let idx = deserialize_u32(expr_bytes, pos);
            (idx as u64)
        }
    }

    fun deserialize_u32(expr_bytes: &vector<u8>, pos: &mut u64): u32 {
        assert!(*pos + 4 <= vector::length(expr_bytes), E_INVALID_BYTES_LENGTH);
        let b0 = *vector::borrow(expr_bytes, *pos);
        let b1 = *vector::borrow(expr_bytes, *pos + 1);
        let b2 = *vector::borrow(expr_bytes, *pos + 2);
        let b3 = *vector::borrow(expr_bytes, *pos + 3);
        *pos = *pos + 4;
        ((b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24))
    }

    public fun compress_exprs(
        exprs: &vector<u8>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<Fr>>,
        advice_evals: &vector<Element<Fr>>,
        fixed_evals: &vector<Element<Fr>>,
        instance_evals: &vector<Element<Fr>>,
        challenges: &vector<Element<Fr>>,
        theta: &Element<Fr>
    ): Element<Fr> {
        let evals = evaluate_exprs(
            exprs,
            use_u8_fields,
            use_u8_queries,
            coeff_pool,
            advice_evals,
            fixed_evals,
            instance_evals,
            challenges
        );

        let acc = crypto_algebra::zero();
        let i = 0;
        let len = vector::length(&evals);
        while (i < len) {
            let eval = vector::borrow(&evals, i);
            acc = crypto_algebra::add(&crypto_algebra::mul(theta, &acc), eval);
            i = i + 1;
        };
        acc
    }
}