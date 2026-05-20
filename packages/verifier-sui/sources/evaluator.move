// Copyright (c) zkMove Authors

module halo2_verifier::evaluator {
    use sui::bn254;
    use sui::group_ops::Element;

    const E_INVALID_POS: u64 = 100;
    const E_INVALID_BYTES_LENGTH: u64 = 101;
    const E_INVALID_FIELD_INDEX: u64 = 102;
    const E_INVALID_FIXED_INDEX: u64 = 103;
    const E_INVALID_ADVICE_INDEX: u64 = 104;
    const E_INVALID_INSTANCE_INDEX: u64 = 105;
    const E_INVALID_CHALLENGE_INDEX: u64 = 106;
    const E_INVALID_NODE_TYPE: u64 = 107;

    public fun evaluate_exprs(
        exprs_bytes: &vector<u8>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        fields_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
    ): vector<Element<bn254::Scalar>> {
        let use_u8_index_for_fields = use_u8_fields == 0;
        let use_u8_index_for_query = use_u8_queries == 0;

        let mut pos = 0;
        let mut results = vector[];
        while (pos < exprs_bytes.length()) {
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

    public fun evaluate_expression(
        expr_bytes: &vector<u8>,
        pos: &mut u64,
        fields_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
        use_u8_index_for_fields: bool,
        use_u8_index_for_query: bool,
    ): Element<bn254::Scalar> {
        assert!(*pos < expr_bytes.length(), E_INVALID_POS);
        let node_type = expr_bytes[*pos];
        *pos = *pos + 1;

        if (node_type == 0x00) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_fields);
            assert!(index < fields_pool.length(), E_INVALID_FIELD_INDEX);
            fields_pool[index]
        } else if (node_type == 0x02) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_query);
            assert!(index < fixed_evals.length(), E_INVALID_FIXED_INDEX);
            fixed_evals[index]
        } else if (node_type == 0x03) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_query);
            assert!(index < advice_evals.length(), E_INVALID_ADVICE_INDEX);
            advice_evals[index]
        } else if (node_type == 0x04) {
            let index = read_index(expr_bytes, pos, use_u8_index_for_query);
            assert!(index < instance_evals.length(), E_INVALID_INSTANCE_INDEX);
            instance_evals[index]
        } else if (node_type == 0x05) {
            let index = deserialize_u32(expr_bytes, pos);
            assert!((index as u64) < challenges.length(), E_INVALID_CHALLENGE_INDEX);
            challenges[index as u64]
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
            bn254::scalar_neg(&value)
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
            bn254::scalar_add(&a, &b)
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
            bn254::scalar_mul(&a, &b)
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
            assert!(index < fields_pool.length(), E_INVALID_FIELD_INDEX);
            bn254::scalar_mul(&value, &fields_pool[index])
        } else {
            abort E_INVALID_NODE_TYPE
        }
    }

    public fun compress_exprs(
        exprs: &vector<u8>,
        use_u8_fields: u8,
        use_u8_queries: u8,
        coeff_pool: &vector<Element<bn254::Scalar>>,
        advice_evals: &vector<Element<bn254::Scalar>>,
        fixed_evals: &vector<Element<bn254::Scalar>>,
        instance_evals: &vector<Element<bn254::Scalar>>,
        challenges: &vector<Element<bn254::Scalar>>,
        theta: &Element<bn254::Scalar>,
    ): Element<bn254::Scalar> {
        let evals = evaluate_exprs(
            exprs,
            use_u8_fields,
            use_u8_queries,
            coeff_pool,
            advice_evals,
            fixed_evals,
            instance_evals,
            challenges,
        );

        let mut acc = bn254::scalar_zero();
        let mut i = 0;
        while (i < evals.length()) {
            acc = bn254::scalar_add(&bn254::scalar_mul(theta, &acc), &evals[i]);
            i = i + 1;
        };
        acc
    }

    fun read_index(expr_bytes: &vector<u8>, pos: &mut u64, use_u8: bool): u64 {
        if (use_u8) {
            assert!(*pos < expr_bytes.length(), E_INVALID_POS);
            let idx = expr_bytes[*pos] as u64;
            *pos = *pos + 1;
            idx
        } else {
            deserialize_u32(expr_bytes, pos) as u64
        }
    }

    fun deserialize_u32(expr_bytes: &vector<u8>, pos: &mut u64): u32 {
        assert!(*pos + 4 <= expr_bytes.length(), E_INVALID_BYTES_LENGTH);
        let b0 = expr_bytes[*pos];
        let b1 = expr_bytes[*pos + 1];
        let b2 = expr_bytes[*pos + 2];
        let b3 = expr_bytes[*pos + 3];
        *pos = *pos + 4;
        ((b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24))
    }
}
