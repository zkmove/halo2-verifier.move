use crate::{CircuitInfo, Column, ColumnQuery, MultiVariatePolynomial};
use halo2_proofs::halo2curves::ff::PrimeField;
use multipoly::multivariate::SparseTerm;

pub struct SerializableCircuitInfo<F: PrimeField> {
    query_instance: bool,
    k: u8,
    max_num_query_of_advice_column: u32,
    cs_degree: u32,
    num_fixed_columns: u64,
    num_instance_columns: u64,
    advice_column_phase: Vec<u8>,
    challenge_phase: Vec<u8>,

    advice_queries: Vec<ColumnQuery>,
    instance_queries: Vec<ColumnQuery>,
    fixed_queries: Vec<ColumnQuery>,
    permutation_columns: Vec<Column>,
    gates: Vec<MultiVariatePolynomial<F>>,
    lookups_input_exprs: Vec<Vec<MultiVariatePolynomial<F>>>,
    lookups_table_exprs: Vec<Vec<MultiVariatePolynomial<F>>>,
}

impl<F: PrimeField> From<CircuitInfo<F>> for SerializableCircuitInfo<F> {
    fn from(
        CircuitInfo {
            query_instance,
            k,
            max_num_query_of_advice_column,
            cs_degree,
            num_fixed_columns,
            num_instance_columns,
            advice_column_phase,
            challenge_phase,
            gates,
            advice_queries,
            instance_queries,
            fixed_queries,
            permutation_columns,
            lookups,
        }: CircuitInfo<F>,
    ) -> Self {
        Self {
            query_instance,
            k,
            max_num_query_of_advice_column,
            cs_degree,
            num_fixed_columns,
            num_instance_columns,
            advice_column_phase,
            challenge_phase,
            advice_queries,
            instance_queries,
            fixed_queries,
            permutation_columns,
            gates: gates.into_iter().flatten().collect(),
            lookups_input_exprs: lookups.iter().map(|l| l.input_exprs.clone()).collect(),
            lookups_table_exprs: lookups.into_iter().map(|l| l.table_exprs).collect(),
        }
    }
}

/// serialize circuit info as a arg list whose elements are nested bytes.
/// the arg list will be part of the txn args for publish circuit verify keys.
pub fn serialize<F: PrimeField>(
    circuit_info: SerializableCircuitInfo<F>,
) -> bcs::Result<Vec<Vec<Vec<u8>>>> {
    let general_info = vec![
        bcs::to_bytes(&circuit_info.query_instance)?,
        bcs::to_bytes(&circuit_info.k)?,
        bcs::to_bytes(&circuit_info.max_num_query_of_advice_column)?,
        bcs::to_bytes(&circuit_info.cs_degree)?,
        bcs::to_bytes(&circuit_info.num_fixed_columns)?,
        bcs::to_bytes(&circuit_info.num_instance_columns)?,
        circuit_info.advice_column_phase,
        circuit_info.challenge_phase,
    ];
    let gates = circuit_info
        .gates
        .iter()
        .map(serialize_multivaiate_poly)
        .collect();
    let advice_queries = circuit_info
        .advice_queries
        .iter()
        .map(serialize_column_query)
        .collect();
    let instance_queries = circuit_info
        .instance_queries
        .iter()
        .map(serialize_column_query)
        .collect();
    let fixed_queries = circuit_info
        .fixed_queries
        .iter()
        .map(serialize_column_query)
        .collect();
    let permutation_columns = circuit_info
        .permutation_columns
        .iter()
        .map(serialize_column)
        .collect();
    let lookups_input_exprs = circuit_info
        .lookups_input_exprs
        .iter()
        .map(serialize_lookup_exprs)
        .collect();
    let lookups_table_exprs = circuit_info
        .lookups_table_exprs
        .iter()
        .map(serialize_lookup_exprs)
        .collect();
    Ok(vec![
        general_info,
        advice_queries,
        instance_queries,
        fixed_queries,
        permutation_columns,
        gates,
        lookups_input_exprs,
        lookups_table_exprs,
    ])
}

fn serialize_column_query(q: &ColumnQuery) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.push(q.column.column_type);
    bytes.extend(q.column.index.to_le_bytes());
    bytes.push(q.rotation.next.into());
    bytes.extend(q.rotation.rotation.to_le_bytes());
    bytes
}

fn serialize_column(column: &Column) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.push(column.column_type);
    bytes.extend(column.index.to_le_bytes());
    bytes
}

fn serialize_multivaiate_poly<F: PrimeField>(poly: &MultiVariatePolynomial<F>) -> Vec<u8> {
    let mut bytes = vec![];
    let term_len = poly.terms.len() as u32;
    bytes.extend(term_len.to_le_bytes());

    poly.terms.iter().for_each(|(coff, term)| {
        bytes.extend(coff.to_repr().as_ref());
        bytes.append(&mut serialize_sparse_term(term));
    });
    bytes
}

fn serialize_sparse_term(t: &SparseTerm) -> Vec<u8> {
    let mut bytes = vec![];
    let t_len = t.len() as u32;
    bytes.extend(t_len.to_le_bytes());
    t.iter().for_each(|(var_idx, power)| {
        bytes.extend((*var_idx as u32).to_le_bytes());
        bytes.extend((*power as u32).to_le_bytes());
    });
    bytes
}

fn serialize_lookup_exprs<F: PrimeField>(
    lookup_input_exprs: &Vec<MultiVariatePolynomial<F>>,
) -> Vec<u8> {
    let mut bytes = vec![];
    let input_expr_len = lookup_input_exprs.len() as u32;
    bytes.extend(input_expr_len.to_le_bytes());
    lookup_input_exprs
        .iter()
        .map(|e| serialize_multivaiate_poly(e))
        .for_each(|mut p| {
            bytes.extend((p.len() as u32).to_le_bytes());
            bytes.append(&mut p);
        });
    bytes
}
