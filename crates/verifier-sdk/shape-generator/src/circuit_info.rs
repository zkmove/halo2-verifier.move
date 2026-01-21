use crate::expression::{deserialize_exprs, serialize_exprs, IndexedExpression};
use crate::helpers::{bytes_to_affines, decode_field, encode_field};
use bcs::Error as BcsError;
use byteorder::{LittleEndian, ReadBytesExt};
use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::Any;
use halo2_proofs::poly::Rotation as Halo2Rotation;
use std::io::Cursor;
use std::marker::PhantomData;

#[derive(Debug, PartialEq, Eq)]
pub struct CircuitInfo<C: CurveAffine> {
    pub(crate) vk_transcript_repr: C::Scalar,
    pub(crate) fixed_commitments: Vec<C>,
    pub(crate) permutation_commitments: Vec<C>,
    pub(crate) k: u8,
    pub(crate) max_num_query_of_advice_column: u32,
    pub(crate) cs_degree: u32,
    pub(crate) num_fixed_columns: u64,
    pub(crate) num_instance_columns: u64,
    pub(crate) advice_column_phase: Vec<u8>,
    pub(crate) challenge_phase: Vec<u8>,
    pub(crate) fields_pool: Vec<C::Scalar>,
    pub(crate) gates: Vec<Gate<C::Scalar>>,
    pub(crate) advice_queries: Vec<ColumnQuery>,
    pub(crate) instance_queries: Vec<ColumnQuery>,
    pub(crate) fixed_queries: Vec<ColumnQuery>,
    pub(crate) permutation_columns: Vec<Column>,
    pub(crate) lookups: Vec<Lookup<C::Scalar>>,
    pub(crate) shuffles: Vec<Shuffle<C::Scalar>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ColumnQuery {
    pub(crate) column: Column,
    pub(crate) rotation: Rotation,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Column {
    pub(crate) index: u32,
    pub(crate) column_type: u8,
}

impl From<halo2_proofs::plonk::Column<Any>> for Column {
    fn from(value: halo2_proofs::plonk::Column<Any>) -> Self {
        let column_type = match value.column_type() {
            Any::Advice => 1,
            Any::Fixed => 2,
            Any::Instance => 3,
        };
        Column {
            index: value.index() as u32,
            column_type,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rotation {
    pub(crate) rotation: u32,
    pub(crate) next: bool,
}

impl From<Halo2Rotation> for Rotation {
    fn from(value: Halo2Rotation) -> Self {
        if value.0.is_negative() {
            Self {
                rotation: value.0.unsigned_abs(),
                next: false,
            }
        } else {
            Self {
                rotation: value.0 as u32,
                next: true,
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Gate<F: Field> {
    pub(crate) polys: Vec<IndexedExpression<F>>,
    pub(crate) _phantom: PhantomData<F>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lookup<F: Field> {
    pub(crate) input_exprs: Vec<IndexedExpression<F>>,
    pub(crate) table_exprs: Vec<IndexedExpression<F>>,
    pub(crate) _phantom: PhantomData<F>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Shuffle<F: Field> {
    pub(crate) input_exprs: Vec<IndexedExpression<F>>,
    pub(crate) shuffle_exprs: Vec<IndexedExpression<F>>,
    pub(crate) _phantom: PhantomData<F>,
}

impl<C: CurveAffine> CircuitInfo<C> {
    /// Serializes CircuitInfo into a Vec<Vec<Vec<u8>>> format (11 sections).
    ///
    /// The output structure is:
    /// 0. general_info (12 items):
    ///    - vk_transcript_repr (bytes)
    ///    - fixed_commitments (concatenated point bytes)
    ///    - permutation_commitments (concatenated point bytes)
    ///    - k (BCS u8)
    ///    - max_num_query_of_advice_column (BCS u32)
    ///    - cs_degree (BCS u32)
    ///    - num_fixed_columns (BCS u64)
    ///    - num_instance_columns (BCS u64)
    ///    - advice_column_phase (raw Vec<u8>)
    ///    - challenge_phase (raw Vec<u8>)
    ///    - use_u8_index_for_query flag (single byte: 0=u8, 1=u32)
    ///    - use_u8_index_for_fields flag (single byte: 0=u8, 1=u32)
    /// 1. advice_queries (each Vec<u8> is serialized ColumnQuery)
    /// 2. instance_queries
    /// 3. fixed_queries
    /// 4. permutation_columns
    /// 5. fields_pool (each Vec<u8> is encoded scalar)
    /// 6. gates (each Vec<u8> is serialized expressions for one gate)
    /// 7. lookups_input_exprs
    /// 8. lookups_table_exprs
    /// 9. shuffles_input_exprs
    /// 10. shuffles_shuffle_exprs
    ///
    /// All expression bytes use the custom binary format defined in serialize_expression.
    pub fn serialize(&self) -> bcs::Result<Vec<Vec<Vec<u8>>>> {
        let vk_repr = PrimeField::to_repr(&self.vk_transcript_repr)
            .as_ref()
            .to_vec();
        let fixed_commitments = self
            .fixed_commitments
            .iter()
            .flat_map(|c| c.to_bytes().as_ref().to_vec())
            .collect();
        let permutation_commitments = self
            .permutation_commitments
            .iter()
            .flat_map(|c| c.to_bytes().as_ref().to_vec())
            .collect();
        let use_u8_index_for_fields = self.fields_pool.len() < 256;
        let use_u8_index_for_query = self.advice_queries.len() < 256
            && self.fixed_queries.len() < 256
            && self.instance_queries.len() < 256;
        let mut general_info = vec![
            vk_repr,
            fixed_commitments,
            permutation_commitments,
            bcs::to_bytes(&self.k)?,
            bcs::to_bytes(&self.max_num_query_of_advice_column)?,
            bcs::to_bytes(&self.cs_degree)?,
            bcs::to_bytes(&self.num_fixed_columns)?,
            bcs::to_bytes(&self.num_instance_columns)?,
            self.advice_column_phase.clone(),
            self.challenge_phase.clone(),
        ];
        // Insert the flags at the beginning of general_info to avoid redundancy per expr group
        general_info.push(vec![if use_u8_index_for_query { 0u8 } else { 1u8 }]);
        general_info.push(vec![if use_u8_index_for_fields { 0u8 } else { 1u8 }]);
        let fields_pool = self
            .fields_pool
            .iter()
            .map(|f| encode_field::<C>(f))
            .collect();
        let gates = self
            .gates
            .iter()
            .map(|g| {
                serialize_exprs::<C>(&g.polys, use_u8_index_for_fields, use_u8_index_for_query)
            })
            .collect::<bcs::Result<Vec<Vec<u8>>>>()?;
        let advice_queries = self
            .advice_queries
            .iter()
            .map(serialize_column_query)
            .collect();
        let instance_queries = self
            .instance_queries
            .iter()
            .map(serialize_column_query)
            .collect();
        let fixed_queries = self
            .fixed_queries
            .iter()
            .map(serialize_column_query)
            .collect();
        let permutation_columns = self
            .permutation_columns
            .iter()
            .map(serialize_column)
            .collect();
        let lookups_input_exprs = self
            .lookups
            .iter()
            .map(|l| {
                serialize_exprs::<C>(
                    &l.input_exprs,
                    use_u8_index_for_fields,
                    use_u8_index_for_query,
                )
            })
            .collect::<bcs::Result<Vec<Vec<u8>>>>()?;
        let lookups_table_exprs = self
            .lookups
            .iter()
            .map(|l| {
                serialize_exprs::<C>(
                    &l.table_exprs,
                    use_u8_index_for_fields,
                    use_u8_index_for_query,
                )
            })
            .collect::<bcs::Result<Vec<Vec<u8>>>>()?;
        let shuffles_input_exprs = self
            .shuffles
            .iter()
            .map(|s| {
                serialize_exprs::<C>(
                    &s.input_exprs,
                    use_u8_index_for_fields,
                    use_u8_index_for_query,
                )
            })
            .collect::<bcs::Result<Vec<Vec<u8>>>>()?;
        let shuffles_shuffle_exprs = self
            .shuffles
            .iter()
            .map(|s| {
                serialize_exprs::<C>(
                    &s.shuffle_exprs,
                    use_u8_index_for_fields,
                    use_u8_index_for_query,
                )
            })
            .collect::<bcs::Result<Vec<Vec<u8>>>>()?;
        let result = vec![
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
        ];

        let item_names = [
            "General Info",
            "Advice Queries",
            "Instance Queries",
            "Fixed Queries",
            "Permutation Columns",
            "Fields Pool",
            "Gates",
            "Lookups Input Expressions",
            "Lookups Table Expressions",
            "Shuffles Input Expressions",
            "Shuffles Shuffle Expressions",
        ];

        for (i, (item, name)) in result.iter().zip(item_names.iter()).enumerate() {
            let total_size: usize = item.iter().map(|nested| nested.len()).sum();
            let lengths = item.len();
            println!(
                "Item {} ({}): total size = {}, lengths = {:?}",
                i, name, total_size, lengths
            );
        }

        Ok(result)
    }

    /// Deserializes the exact format produced by serialize().
    ///
    /// Expects exactly 11 top-level sections.
    /// See serialize() docs for section meanings.
    pub fn deserialize(data: Vec<Vec<Vec<u8>>>) -> bcs::Result<CircuitInfo<C>> {
        if data.len() != 11 {
            return Err(BcsError::Custom(format!(
                "Expected 11 sections, got {}",
                data.len()
            )));
        }

        let mut sections = data.into_iter();

        // 0. general_info
        let general_info = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing general_info section".to_string()))?;
        if general_info.len() != 12 {
            return Err(BcsError::Custom(format!(
                "general_info expected 12 items, got {}",
                general_info.len()
            )));
        }

        let mut general_iter = general_info.into_iter();

        let vk_repr_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing vk_repr".to_string()))?;
        let fixed_commitments_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing fixed_commitments".to_string()))?;
        let permutation_commitments_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing permutation_commitments".to_string()))?;
        let k_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing k".to_string()))?;
        let max_num_query_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing max_num_query".to_string()))?;
        let cs_degree_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing cs_degree".to_string()))?;
        let num_fixed_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing num_fixed_columns".to_string()))?;
        let num_instance_bytes = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing num_instance_columns".to_string()))?;
        let advice_column_phase = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing advice_column_phase".to_string()))?;
        let challenge_phase = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing challenge_phase".to_string()))?;

        let use_u8_index_for_query_flag = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing query flag".to_string()))?;
        let use_u8_index_for_fields_flag = general_iter
            .next()
            .ok_or_else(|| BcsError::Custom("Missing fields flag".to_string()))?;

        if general_iter.next().is_some() {
            return Err(BcsError::Custom("Extra items in general_info".to_string()));
        }

        // vk_transcript_repr
        let repr_size = 32; // bn256 Fr Repr = 32 bytes (compressed scalar)
        if vk_repr_bytes.len() != repr_size {
            return Err(BcsError::Custom(format!(
                "vk_repr wrong length: expected {}, got {}",
                repr_size,
                vk_repr_bytes.len()
            )));
        }

        let mut repr = <C::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&vk_repr_bytes);
        let vk_transcript_repr = <C::Scalar as PrimeField>::from_repr(repr)
            .into_option()
            .ok_or_else(|| {
                BcsError::Custom("Invalid vk_transcript_repr bytes (from_repr failed)".to_string())
            })?;

        let k: u8 = bcs::from_bytes(&k_bytes)?;
        let max_num_query_of_advice_column: u32 = bcs::from_bytes(&max_num_query_bytes)?;
        let cs_degree: u32 = bcs::from_bytes(&cs_degree_bytes)?;
        let num_fixed_columns: u64 = bcs::from_bytes(&num_fixed_bytes)?;
        let num_instance_columns: u64 = bcs::from_bytes(&num_instance_bytes)?;

        let use_u8_index_for_query = use_u8_index_for_query_flag == vec![0u8];
        let use_u8_index_for_fields = use_u8_index_for_fields_flag == vec![0u8];

        // fixed_commitments & permutation_commitments
        let fixed_commitments = bytes_to_affines::<C>(&fixed_commitments_bytes)
            .map_err(|e| BcsError::Custom(format!("Invalid fixed_commitments: {}", e)))?;

        let permutation_commitments = bytes_to_affines::<C>(&permutation_commitments_bytes)
            .map_err(|e| BcsError::Custom(format!("Invalid permutation_commitments: {}", e)))?;

        // queries & columns
        let advice_queries = deserialize_column_queries(
            sections
                .next()
                .ok_or_else(|| BcsError::Custom("Missing advice_queries".to_string()))?,
        )
        .map_err(|e| BcsError::Custom(format!("Failed to deserialize advice_queries: {}", e)))?;

        let instance_queries = deserialize_column_queries(
            sections
                .next()
                .ok_or_else(|| BcsError::Custom("Missing instance_queries".to_string()))?,
        )
        .map_err(|e| BcsError::Custom(format!("Failed to deserialize instance_queries: {}", e)))?;

        let fixed_queries = deserialize_column_queries(
            sections
                .next()
                .ok_or_else(|| BcsError::Custom("Missing fixed_queries".to_string()))?,
        )
        .map_err(|e| BcsError::Custom(format!("Failed to deserialize fixed_queries: {}", e)))?;

        let permutation_columns = deserialize_columns(
            sections
                .next()
                .ok_or_else(|| BcsError::Custom("Missing permutation_columns".to_string()))?,
        )
        .map_err(|e| {
            BcsError::Custom(format!("Failed to deserialize permutation_columns: {}", e))
        })?;

        // fields_pool
        let fields_pool_bytes = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing fields_pool".to_string()))?;
        let fields_pool = fields_pool_bytes
            .iter()
            .enumerate()
            .map(|(i, f_bytes)| {
                decode_field::<C>(f_bytes).ok_or_else(|| {
                    BcsError::Custom(format!("Invalid scalar in fields_pool at index {}", i))
                })
            })
            .collect::<bcs::Result<Vec<_>>>()?;

        // expressions
        let gates_bytes = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing gates".to_string()))?;
        let gates = deserialize_gates::<C>(
            gates_bytes,
            use_u8_index_for_fields,
            use_u8_index_for_query,
            &challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Failed to deserialize gates: {}", e)))?;

        let lookups_input_bytes = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing lookups_input".to_string()))?;
        let lookups_table_bytes = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing lookups_table".to_string()))?;
        let lookups = deserialize_lookups::<C>(
            &lookups_input_bytes,
            &lookups_table_bytes,
            use_u8_index_for_fields,
            use_u8_index_for_query,
            &challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Failed to deserialize lookups: {}", e)))?;

        let shuffles_input_bytes = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing shuffles_input".to_string()))?;
        let shuffles_shuffle_bytes = sections
            .next()
            .ok_or_else(|| BcsError::Custom("Missing shuffles_shuffle".to_string()))?;
        let shuffles = deserialize_shuffles::<C>(
            &shuffles_input_bytes,
            &shuffles_shuffle_bytes,
            use_u8_index_for_fields,
            use_u8_index_for_query,
            &challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Failed to deserialize shuffles: {}", e)))?;

        if sections.next().is_some() {
            return Err(BcsError::Custom("Extra sections found".to_string()));
        }

        Ok(CircuitInfo {
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
            fields_pool,
            gates,
            advice_queries,
            instance_queries,
            fixed_queries,
            permutation_columns,
            lookups,
            shuffles,
        })
    }
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

fn deserialize_column_queries(bytes_list: Vec<Vec<u8>>) -> bcs::Result<Vec<ColumnQuery>> {
    bytes_list
        .into_iter()
        .map(|bytes| {
            if bytes.len() != 1 + 4 + 1 + 4 {
                return Err(BcsError::Custom(format!(
                    "ColumnQuery wrong size: expected 10 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut cur = Cursor::new(bytes);
            let column_type = cur.read_u8().map_err(|e| BcsError::Custom(e.to_string()))?;
            let index = cur
                .read_u32::<LittleEndian>()
                .map_err(|e| BcsError::Custom(e.to_string()))?;
            let next_byte = cur.read_u8().map_err(|e| BcsError::Custom(e.to_string()))?;
            let next = next_byte != 0;
            let rotation = cur
                .read_u32::<LittleEndian>()
                .map_err(|e| BcsError::Custom(e.to_string()))?;

            Ok(ColumnQuery {
                column: Column { index, column_type },
                rotation: Rotation { rotation, next },
            })
        })
        .collect()
}

fn deserialize_columns(bytes_list: Vec<Vec<u8>>) -> bcs::Result<Vec<Column>> {
    bytes_list
        .into_iter()
        .map(|bytes| {
            if bytes.len() != 1 + 4 {
                return Err(BcsError::Custom(format!(
                    "Column wrong size: expected 5 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut cur = Cursor::new(bytes);
            let column_type = cur.read_u8().map_err(|e| BcsError::Custom(e.to_string()))?;
            let index = cur
                .read_u32::<LittleEndian>()
                .map_err(|e| BcsError::Custom(e.to_string()))?;
            Ok(Column { index, column_type })
        })
        .collect()
}

fn deserialize_gates<C: CurveAffine>(
    bytes_list: Vec<Vec<u8>>,
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<Vec<Gate<C::Scalar>>> {
    bytes_list
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| {
            let polys =
                deserialize_exprs::<C>(&bytes, use_u8_fields, use_u8_query, challenge_phase)
                    .map_err(|e| {
                        BcsError::Custom(format!("Gate[{}] expression error: {}", i, e))
                    })?;
            Ok(Gate {
                polys,
                _phantom: PhantomData,
            })
        })
        .collect()
}

fn deserialize_lookups<C: CurveAffine>(
    input_bytes_list: &[Vec<u8>],
    table_bytes_list: &[Vec<u8>],
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<Vec<Lookup<C::Scalar>>> {
    if input_bytes_list.len() != table_bytes_list.len() {
        return Err(BcsError::Custom(format!(
            "Lookups input and table lengths mismatch: {} vs {}",
            input_bytes_list.len(),
            table_bytes_list.len()
        )));
    }

    let mut lookups = Vec::with_capacity(input_bytes_list.len());
    for i in 0..input_bytes_list.len() {
        let input_exprs = deserialize_exprs::<C>(
            &input_bytes_list[i],
            use_u8_fields,
            use_u8_query,
            challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Lookups[{}] input expr error: {}", i, e)))?;

        let table_exprs = deserialize_exprs::<C>(
            &table_bytes_list[i],
            use_u8_fields,
            use_u8_query,
            challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Lookups[{}] table expr error: {}", i, e)))?;

        lookups.push(Lookup {
            input_exprs,
            table_exprs,
            _phantom: PhantomData,
        });
    }
    Ok(lookups)
}

fn deserialize_shuffles<C: CurveAffine>(
    input_bytes_list: &[Vec<u8>],
    shuffle_bytes_list: &[Vec<u8>],
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<Vec<Shuffle<C::Scalar>>> {
    if input_bytes_list.len() != shuffle_bytes_list.len() {
        return Err(BcsError::Custom(format!(
            "Shuffles input and shuffle lengths mismatch: {} vs {}",
            input_bytes_list.len(),
            shuffle_bytes_list.len()
        )));
    }

    let mut shuffles = Vec::with_capacity(input_bytes_list.len());
    for i in 0..input_bytes_list.len() {
        let input_exprs = deserialize_exprs::<C>(
            &input_bytes_list[i],
            use_u8_fields,
            use_u8_query,
            challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Shuffles[{}] input expr error: {}", i, e)))?;

        let shuffle_exprs = deserialize_exprs::<C>(
            &shuffle_bytes_list[i],
            use_u8_fields,
            use_u8_query,
            challenge_phase,
        )
        .map_err(|e| BcsError::Custom(format!("Shuffles[{}] shuffle expr error: {}", i, e)))?;

        shuffles.push(Shuffle {
            input_exprs,
            shuffle_exprs,
            _phantom: PhantomData,
        });
    }
    Ok(shuffles)
}
