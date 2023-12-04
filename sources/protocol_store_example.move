module halo2_verifier::protocol_store_example {
    use std::vector;
    use aptos_std::from_bcs;

    public entry fun decode_protocol(
        general_info: vector<vector<u8>>,
        advice_queries: vector<vector<u8>>,
        instance_queries: vector<vector<u8>>,
        fixed_queries: vector<vector<u8>>,
        permutation_columns: vector<vector<u8>>,
        gates: vector<vector<u8>>,
        lookups_input_exprs: vector<vector<u8>>,
        lookups_table_exprs: vector<vector<u8>>,
    ) {
        let challenge_phase = vector::pop_back(&mut general_info);
        let advice_column_phase = vector::pop_back(&mut general_info);
        let num_instance_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let num_fixed_columns = from_bcs::to_u64(vector::pop_back(&mut general_info));
        let cs_degree = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let max_num_query_of_advice_column = from_bcs::to_u32(vector::pop_back(&mut general_info));
        let k = from_bcs::to_u8(vector::pop_back(&mut general_info));
        let query_instance = from_bcs::to_bool(vector::pop_back(&mut general_info));
    }
}
