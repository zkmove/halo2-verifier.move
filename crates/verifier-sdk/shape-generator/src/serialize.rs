use crate::{CircuitInfo, Column, ColumnQuery};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::PrimeField;
use multipoly::multivariate::SparseTerm;

pub struct SerializableCircuitInfo<C: CurveAffine> {
    vk_transcript_repr: C::Scalar,
    fixed_commitments: Vec<C>,
    permutation_commitments: Vec<C>,
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

    fields_pool: Vec<C::Scalar>,
    gates: Vec<IndexedMultiVariatePolynomial>,
    lookups_input_exprs: Vec<Vec<IndexedMultiVariatePolynomial>>,
    lookups_table_exprs: Vec<Vec<IndexedMultiVariatePolynomial>>,
    shuffles_input_exprs: Vec<Vec<IndexedMultiVariatePolynomial>>,
    shuffles_exprs: Vec<Vec<IndexedMultiVariatePolynomial>>,
}

type IndexedMultiVariatePolynomial = Vec<(u16, SparseTerm)>;

fn index_element<T: Eq>(pool: &mut Vec<T>, elem: T) -> usize {
    if let Some(pos) = pool.iter().position(|e| e == &elem) {
        pos
    } else {
        pool.push(elem);
        pool.len() - 1
    }
}

impl<C: CurveAffine> From<CircuitInfo<C>> for SerializableCircuitInfo<C> {
    fn from(
        CircuitInfo {
            vk_transcript_repr,
            fixed_commitments,
            permutation_commitments,
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
            shuffles,
        }: CircuitInfo<C>,
    ) -> Self {
        let mut fields_pool: Vec<C::Scalar> = Vec::new();
        let gates: Vec<_> = gates
            .iter()
            .flatten()
            .map(|expr| {
                expr.terms
                    .iter()
                    .map(|(coff, t)| {
                        let new_coff = index_element(&mut fields_pool, *coff);
                        (new_coff as u16, t.clone())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let lookups_len = lookups.len();
        let (inputs, tables) = lookups.into_iter().fold(
            (
                Vec::with_capacity(lookups_len),
                Vec::with_capacity(lookups_len),
            ),
            |(mut inputs, mut tables), l| {
                inputs.push(
                    l.input_exprs
                        .into_iter()
                        .map(|expr| {
                            expr.terms
                                .iter()
                                .map(|(coff, t)| {
                                    let new_coff = index_element(&mut fields_pool, *coff);
                                    (new_coff as u16, t.clone())
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                );
                tables.push(
                    l.table_exprs
                        .into_iter()
                        .map(|expr| {
                            expr.terms
                                .iter()
                                .map(|(coff, t)| {
                                    let new_coff = index_element(&mut fields_pool, *coff);
                                    (new_coff as u16, t.clone())
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                );
                (inputs, tables)
            },
        );
        let shuffles_len = shuffles.len();
        let (shuffles_input, shuffles_shuffle) = shuffles.into_iter().fold(
            (
                Vec::with_capacity(shuffles_len),
                Vec::with_capacity(shuffles_len),
            ),
            |(mut shuffle_inputs, mut shuffles), s| {
                shuffle_inputs.push(
                    s.input_exprs
                        .into_iter()
                        .map(|expr| {
                            expr.terms
                                .iter()
                                .map(|(coff, t)| {
                                    let new_coff = index_element(&mut fields_pool, *coff);
                                    (new_coff as u16, t.clone())
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                );
                shuffles.push(
                    s.shuffle_exprs
                        .into_iter()
                        .map(|expr| {
                            expr.terms
                                .iter()
                                .map(|(coff, t)| {
                                    let new_coff = index_element(&mut fields_pool, *coff);
                                    (new_coff as u16, t.clone())
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                );
                (shuffle_inputs, shuffles)
            },
        );

        Self {
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

            gates,
            lookups_input_exprs: inputs,
            lookups_table_exprs: tables,
            shuffles_input_exprs: shuffles_input,
            shuffles_exprs: shuffles_shuffle,
            fields_pool,
            vk_transcript_repr,
            fixed_commitments,
            permutation_commitments,
        }
    }
}

/// serialize circuit info as a arg list whose elements are nested bytes.
/// the arg list will be part of the txn args for publish circuit verify keys.
pub fn serialize<C: CurveAffine>(
    circuit_info: SerializableCircuitInfo<C>,
) -> bcs::Result<Vec<Vec<Vec<u8>>>> {
    let vk_repr = PrimeField::to_repr(&circuit_info.vk_transcript_repr)
        .as_ref()
        .to_vec();
    let fixed_commitments = circuit_info
        .fixed_commitments
        .iter()
        .flat_map(|c| c.to_bytes().as_ref().to_vec())
        .collect();
    let permutation_commitments = circuit_info
        .permutation_commitments
        .iter()
        .flat_map(|c| c.to_bytes().as_ref().to_vec())
        .collect();
    let general_info = vec![
        vk_repr,
        fixed_commitments,
        permutation_commitments,
        bcs::to_bytes(&circuit_info.k)?,
        bcs::to_bytes(&circuit_info.max_num_query_of_advice_column)?,
        bcs::to_bytes(&circuit_info.cs_degree)?,
        bcs::to_bytes(&circuit_info.num_fixed_columns)?,
        bcs::to_bytes(&circuit_info.num_instance_columns)?,
        circuit_info.advice_column_phase,
        circuit_info.challenge_phase,
    ];
    let fields_pool: Vec<_> = circuit_info
        .fields_pool
        .into_iter()
        .map(|elem| elem.to_repr().as_ref().to_vec())
        .collect();
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
    let shuffles_input_exprs = circuit_info
        .shuffles_input_exprs
        .iter()
        .map(serialize_lookup_exprs)
        .collect();
    let shuffles_shuffle_exprs = circuit_info
        .shuffles_exprs
        .iter()
        .map(serialize_lookup_exprs)
        .collect();
    Ok(vec![
        general_info,
        advice_queries,
        instance_queries,
        fixed_queries,
        permutation_columns,
        fields_pool,
        gates,
        lookups_input_exprs,
        lookups_table_exprs,
        shuffles_input_exprs,
        shuffles_shuffle_exprs,
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

fn serialize_multivaiate_poly(poly: &IndexedMultiVariatePolynomial) -> Vec<u8> {
    let mut bytes = vec![];
    let term_len = poly.len() as u32;
    bytes.extend(term_len.to_le_bytes());

    poly.iter().for_each(|(coff, term)| {
        bytes.extend(coff.to_le_bytes());
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

fn serialize_lookup_exprs(lookup_input_exprs: &Vec<IndexedMultiVariatePolynomial>) -> Vec<u8> {
    let mut bytes = vec![];
    let input_expr_len = lookup_input_exprs.len() as u32;
    bytes.extend(input_expr_len.to_le_bytes());
    lookup_input_exprs
        .iter()
        .map(serialize_multivaiate_poly)
        .for_each(|mut p| {
            bytes.extend((p.len() as u32).to_le_bytes());
            bytes.append(&mut p);
        });
    bytes
}
