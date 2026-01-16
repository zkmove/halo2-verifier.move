use bcs::Error as BcsError;
use byteorder::{LittleEndian, ReadBytesExt};
use halo2_backend::plonk::{
    ConstraintSystemBack as ConstraintSystem, ExpressionBack as Expression, VarBack,
};
use halo2_middleware::circuit::ChallengeMid as Challenge;
use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::plonk::{keygen_vk, Any, Circuit, Error, ErrorFront};
use halo2_proofs::poly::commitment::Params;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::marker::PhantomData;

mod test;

#[derive(Debug, PartialEq, Eq)]
pub struct CircuitInfo<C: CurveAffine> {
    pub vk_transcript_repr: C::Scalar,
    pub fixed_commitments: Vec<C>,
    pub permutation_commitments: Vec<C>,
    pub k: u8,
    pub max_num_query_of_advice_column: u32,
    pub cs_degree: u32,
    pub num_fixed_columns: u64,
    pub num_instance_columns: u64,
    pub advice_column_phase: Vec<u8>,
    pub challenge_phase: Vec<u8>,
    pub fields_pool: Vec<C::Scalar>,
    pub gates: Vec<Gate<C::Scalar>>,
    pub advice_queries: Vec<ColumnQuery>,
    pub instance_queries: Vec<ColumnQuery>,
    pub fixed_queries: Vec<ColumnQuery>,
    pub permutation_columns: Vec<Column>,
    pub lookups: Vec<Lookup<C::Scalar>>,
    pub shuffles: Vec<Shuffle<C::Scalar>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ColumnQuery {
    pub column: Column,
    pub rotation: Rotation,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Column {
    pub index: u32,
    pub column_type: u8,
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
pub struct Rotation {
    pub rotation: u32,
    pub next: bool,
}

impl From<halo2_proofs::poly::Rotation> for Rotation {
    fn from(value: halo2_proofs::poly::Rotation) -> Self {
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
pub struct Gate<F: Field> {
    pub polys: Vec<IndexedExpression<F>>,
    _phantom: PhantomData<F>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Lookup<F: Field> {
    pub input_exprs: Vec<IndexedExpression<F>>,
    pub table_exprs: Vec<IndexedExpression<F>>,
    _phantom: PhantomData<F>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Shuffle<F: Field> {
    pub input_exprs: Vec<IndexedExpression<F>>,
    pub shuffle_exprs: Vec<IndexedExpression<F>>,
    _phantom: PhantomData<F>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexType {
    U8(u8),
    U32(u32),
}

impl IndexType {
    pub fn value(&self) -> u32 {
        match self {
            IndexType::U8(v) => *v as u32,
            IndexType::U32(v) => *v,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexedExpression<F: Field> {
    ConstantIndex(IndexType, PhantomData<F>),
    Fixed(IndexType),
    Advice(IndexType),
    Instance(IndexType),
    Challenge(Challenge),
    Negated(Box<IndexedExpression<F>>),
    Sum(Box<IndexedExpression<F>>, Box<IndexedExpression<F>>),
    Product(Box<IndexedExpression<F>>, Box<IndexedExpression<F>>),
    Scaled(Box<IndexedExpression<F>>, IndexType),
}
impl<F: Field> IndexedExpression<F> {
    fn write_identifier<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            IndexedExpression::ConstantIndex(index, _) => {
                write!(writer, "constant_index[{}]", index.value())
            }
            IndexedExpression::Fixed(index) => {
                write!(writer, "fixed_query[{}]", index.value())
            }
            IndexedExpression::Advice(index) => {
                write!(writer, "advice_query[{}]", index.value())
            }
            IndexedExpression::Instance(index) => {
                write!(writer, "instance_query[{}]", index.value())
            }
            IndexedExpression::Challenge(challenge) => {
                write!(writer, "challenge[{}]", challenge.index)
            }
            IndexedExpression::Negated(a) => {
                writer.write_all(b"(-")?;
                a.write_identifier(writer)?;
                writer.write_all(b")")
            }
            IndexedExpression::Sum(a, b) => {
                writer.write_all(b"(")?;
                a.write_identifier(writer)?;
                writer.write_all(b"+")?;
                b.write_identifier(writer)?;
                writer.write_all(b")")
            }
            IndexedExpression::Product(a, b) => {
                writer.write_all(b"(")?;
                a.write_identifier(writer)?;
                writer.write_all(b"*")?;
                b.write_identifier(writer)?;
                writer.write_all(b")")
            }
            IndexedExpression::Scaled(expr, index) => {
                expr.write_identifier(writer)?;
                write!(writer, "*constant_index[{}]", index.value())
            }
        }
    }

    pub fn identifier(&self) -> String {
        let mut cursor = std::io::Cursor::new(Vec::new());
        self.write_identifier(&mut cursor).unwrap();
        String::from_utf8(cursor.into_inner()).unwrap()
    }
}

fn collect_fields<C: CurveAffine>(
    expr: &Expression<C::Scalar>,
    fields_pool: &mut Vec<C::Scalar>,
    constant_map: &mut HashMap<Vec<u8>, u32>,
) {
    match expr {
        Expression::Constant(f) => {
            let bytes = encode_field::<C>(f);
            constant_map.entry(bytes).or_insert_with(|| {
                let idx = fields_pool.len() as u32;
                fields_pool.push(*f);
                idx
            });
        }
        Expression::Var(_) => {}
        Expression::Negated(e) => collect_fields::<C>(e, fields_pool, constant_map),
        Expression::Sum(a, b) => {
            collect_fields::<C>(a, fields_pool, constant_map);
            collect_fields::<C>(b, fields_pool, constant_map);
        }
        Expression::Product(a, b) => {
            collect_fields::<C>(a, fields_pool, constant_map);
            collect_fields::<C>(b, fields_pool, constant_map);
        }
    }
}

#[allow(clippy::only_used_in_recursion)]
fn to_indexed_expression<C: CurveAffine>(
    expr: &Expression<C::Scalar>,
    constant_map: &HashMap<Vec<u8>, u32>,
    use_u8_index_for_fields: bool,
    use_u8_index_for_query: bool,
    cs: &ConstraintSystem<C::Scalar>,
) -> Result<IndexedExpression<C::Scalar>, Error> {
    match expr {
        Expression::Constant(f) => {
            let bytes = encode_field::<C>(f);
            let index = *constant_map
                .get(&bytes)
                .ok_or(ErrorFront::Other("Constant not found".to_string()))?;
            let idx = if use_u8_index_for_fields {
                if index >= 256 {
                    return Err(ErrorFront::Other("Index exceeds limit".to_string()).into());
                }
                IndexType::U8(index as u8)
            } else {
                IndexType::U32(index)
            };
            Ok(IndexedExpression::ConstantIndex(idx, PhantomData))
        }
        Expression::Var(v) => match v {
            VarBack::Query(q) => {
                let index = q.index;
                let idx = if use_u8_index_for_query {
                    if index >= 256 {
                        return Err(ErrorFront::Other("Index exceeds limit".to_string()).into());
                    }
                    IndexType::U8(index as u8)
                } else {
                    IndexType::U32(index as u32)
                };
                match q.column_type {
                    Any::Fixed => Ok(IndexedExpression::Fixed(idx)),
                    Any::Advice => Ok(IndexedExpression::Advice(idx)),
                    Any::Instance => Ok(IndexedExpression::Instance(idx)),
                }
            }
            VarBack::Challenge(c) => Ok(IndexedExpression::Challenge(*c)),
        },
        Expression::Negated(e) => {
            let e_expr = to_indexed_expression::<C>(
                e,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            Ok(IndexedExpression::Negated(Box::new(e_expr)))
        }
        Expression::Sum(a, b) => {
            let a_expr = to_indexed_expression::<C>(
                a,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            let b_expr = to_indexed_expression::<C>(
                b,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            Ok(IndexedExpression::Sum(Box::new(a_expr), Box::new(b_expr)))
        }
        Expression::Product(a, b) => {
            let a_expr = to_indexed_expression::<C>(
                a,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            let b_expr = to_indexed_expression::<C>(
                b,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            if let IndexedExpression::ConstantIndex(idx, _) = &a_expr {
                Ok(IndexedExpression::Scaled(Box::new(b_expr), *idx))
            } else if let IndexedExpression::ConstantIndex(idx, _) = &b_expr {
                Ok(IndexedExpression::Scaled(Box::new(a_expr), *idx))
            } else {
                Ok(IndexedExpression::Product(
                    Box::new(a_expr),
                    Box::new(b_expr),
                ))
            }
        }
    }
}

pub fn generate_circuit_info<C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
) -> Result<CircuitInfo<C>, Error>
where
    C: CurveAffine,
    P: Params<C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: FromUniformBytes<64>,
    C::ScalarExt: FromUniformBytes<64>,
{
    let vk = keygen_vk(params, circuit)?;
    let cs = vk.cs().clone();

    let vk_repr = {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();
        let s = format!("{:?}", vk.pinned());
        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());
        C::Scalar::from_uniform_bytes(hasher.finalize().as_array())
    };

    let mut fields_pool: Vec<C::Scalar> = Vec::new();
    let mut constant_map: HashMap<Vec<u8>, u32> = HashMap::new();

    for gate in cs.gates() {
        collect_fields::<C>(gate.polynomial(), &mut fields_pool, &mut constant_map);
    }
    for lookup in cs.lookups() {
        for expr in &lookup.input_expressions {
            collect_fields::<C>(expr, &mut fields_pool, &mut constant_map);
        }
        for expr in &lookup.table_expressions {
            collect_fields::<C>(expr, &mut fields_pool, &mut constant_map);
        }
    }
    for shuffle in cs.shuffles() {
        for expr in &shuffle.input_expressions {
            collect_fields::<C>(expr, &mut fields_pool, &mut constant_map);
        }
        for expr in &shuffle.shuffle_expressions {
            collect_fields::<C>(expr, &mut fields_pool, &mut constant_map);
        }
    }

    let use_u8_index_for_fields = fields_pool.len() < 256;
    let use_u8_index_for_query = cs.advice_queries().len() < 256
        && cs.fixed_queries().len() < 256
        && cs.instance_queries().len() < 256;

    let gates: Vec<Gate<C::Scalar>> = cs
        .gates()
        .iter()
        .map(|g| {
            let polys: Vec<IndexedExpression<C::Scalar>> = vec![to_indexed_expression::<C>(
                g.polynomial(),
                &constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                &cs,
            )?];
            Ok(Gate {
                polys,
                _phantom: PhantomData,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let lookups: Vec<Lookup<C::Scalar>> = cs
        .lookups()
        .iter()
        .map(|l| {
            let input_exprs: Vec<IndexedExpression<C::Scalar>> = l
                .input_expressions
                .iter()
                .map(|e| {
                    to_indexed_expression::<C>(
                        e,
                        &constant_map,
                        use_u8_index_for_fields,
                        use_u8_index_for_query,
                        &cs,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let table_exprs: Vec<IndexedExpression<C::Scalar>> = l
                .table_expressions
                .iter()
                .map(|e| {
                    to_indexed_expression::<C>(
                        e,
                        &constant_map,
                        use_u8_index_for_fields,
                        use_u8_index_for_query,
                        &cs,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(Lookup {
                input_exprs,
                table_exprs,
                _phantom: PhantomData,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let shuffles: Vec<Shuffle<C::Scalar>> = cs
        .shuffles()
        .iter()
        .map(|s| {
            let input_exprs: Vec<IndexedExpression<C::Scalar>> = s
                .input_expressions
                .iter()
                .map(|e| {
                    to_indexed_expression::<C>(
                        e,
                        &constant_map,
                        use_u8_index_for_fields,
                        use_u8_index_for_query,
                        &cs,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let shuffle_exprs: Vec<IndexedExpression<C::Scalar>> = s
                .shuffle_expressions
                .iter()
                .map(|e| {
                    to_indexed_expression::<C>(
                        e,
                        &constant_map,
                        use_u8_index_for_fields,
                        use_u8_index_for_query,
                        &cs,
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(Shuffle {
                input_exprs,
                shuffle_exprs,
                _phantom: PhantomData,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let info = CircuitInfo {
        vk_transcript_repr: vk_repr,
        fixed_commitments: vk.fixed_commitments().clone(),
        permutation_commitments: vk.permutation().commitments().to_vec(),
        k: params.k() as u8,
        cs_degree: cs.degree() as u32,
        num_fixed_columns: cs.num_fixed_columns() as u64,
        num_instance_columns: cs.num_instance_columns() as u64,
        advice_column_phase: cs.advice_column_phase().to_vec(),
        challenge_phase: cs.challenge_phase().to_vec(),
        fields_pool,
        gates,
        advice_queries: cs
            .advice_queries()
            .iter()
            .map(|(c, r)| ColumnQuery {
                column: halo2_proofs::plonk::Column::<Any>::from(*c).into(),
                rotation: From::from(*r),
            })
            .collect(),
        instance_queries: cs
            .instance_queries()
            .iter()
            .map(|(c, r)| ColumnQuery {
                column: halo2_proofs::plonk::Column::<Any>::from(*c).into(),
                rotation: From::from(*r),
            })
            .collect(),
        fixed_queries: cs
            .fixed_queries()
            .iter()
            .map(|(c, r)| ColumnQuery {
                column: halo2_proofs::plonk::Column::<Any>::from(*c).into(),
                rotation: From::from(*r),
            })
            .collect(),
        permutation_columns: cs
            .permutation()
            .columns
            .iter()
            .map(|c| From::<halo2_proofs::plonk::Column<Any>>::from((*c).into()))
            .collect(),
        lookups,
        shuffles,
        max_num_query_of_advice_column: cs
            .advice_queries()
            .iter()
            .fold(BTreeMap::default(), |mut m, (c, _r)| {
                if let std::collections::btree_map::Entry::Vacant(e) = m.entry(c.index) {
                    e.insert(1u32);
                } else {
                    *m.get_mut(&c.index).unwrap() += 1;
                }
                m
            })
            .values()
            .max()
            .cloned()
            .unwrap_or_default(),
    };
    Ok(info)
}

fn encode_field<C: CurveAffine>(f: &C::Scalar) -> Vec<u8> {
    PrimeField::to_repr(f).as_ref().to_vec()
}

fn decode_field<C: CurveAffine>(data: &[u8]) -> Option<C::Scalar> {
    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(data);
    <C::Scalar as PrimeField>::from_repr(repr).into()
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

fn serialize_exprs<C: CurveAffine>(
    exprs: &[IndexedExpression<C::Scalar>],
    use_u8_index_for_fields: bool,
    use_u8_index_for_query: bool,
) -> bcs::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for expr in exprs {
        serialize_expression::<C>(
            expr,
            &mut bytes,
            use_u8_index_for_fields,
            use_u8_index_for_query,
        )?;
    }
    Ok(bytes)
}

fn serialize_index(buffer: &mut Vec<u8>, index: &IndexType, use_u8: bool) -> bcs::Result<()> {
    match index {
        IndexType::U8(idx) => {
            if !use_u8 {
                return Err(BcsError::Custom(
                    "use_u8=false but found U8 index (inconsistent flag)".to_string(),
                ));
            }
            buffer.push(*idx);
        }
        IndexType::U32(idx) => {
            if use_u8 {
                return Err(BcsError::Custom(
                    "use_u8=true but found U32 index (inconsistent flag)".to_string(),
                ));
            }
            buffer.extend(idx.to_le_bytes());
        }
    }
    Ok(())
}

/// Serializes IndexedExpression to custom binary format:
/// tag (1 byte) + payload
/// Tags:
/// 0x00 - ConstantIndex: tag + index (u8/u32)
/// 0x02 - Fixed:       tag + index
/// 0x03 - Advice:      tag + index
/// 0x04 - Instance:    tag + index
/// 0x05 - Challenge:   tag + u32 index
/// 0x06 - Negated:     tag + child expr
/// 0x07 - Sum:         tag + left + right
/// 0x08 - Product:     tag + left + right
/// 0x09 - Scaled:      tag + child expr + scalar index
fn serialize_expression<C: CurveAffine>(
    expr: &IndexedExpression<C::Scalar>,
    buffer: &mut Vec<u8>,
    use_u8_index_for_fields: bool,
    use_u8_index_for_query: bool,
) -> bcs::Result<()> {
    match expr {
        IndexedExpression::ConstantIndex(index, _) => {
            buffer.push(0x00);
            serialize_index(buffer, index, use_u8_index_for_fields)?;
        }
        IndexedExpression::Fixed(index) => {
            buffer.push(0x02);
            serialize_index(buffer, index, use_u8_index_for_query)?;
        }
        IndexedExpression::Advice(index) => {
            buffer.push(0x03);
            serialize_index(buffer, index, use_u8_index_for_query)?;
        }
        IndexedExpression::Instance(index) => {
            buffer.push(0x04);
            serialize_index(buffer, index, use_u8_index_for_query)?;
        }
        IndexedExpression::Challenge(challenge) => {
            buffer.push(0x05);
            let index = challenge.index() as u32;
            buffer.extend(index.to_le_bytes());
        }
        IndexedExpression::Negated(expr) => {
            buffer.push(0x06);
            serialize_expression::<C>(
                expr,
                buffer,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            )?;
        }
        IndexedExpression::Sum(a, b) => {
            buffer.push(0x07);
            serialize_expression::<C>(a, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
            serialize_expression::<C>(b, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
        }
        IndexedExpression::Product(a, b) => {
            buffer.push(0x08);
            serialize_expression::<C>(a, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
            serialize_expression::<C>(b, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
        }
        IndexedExpression::Scaled(expr, index) => {
            buffer.push(0x09);
            serialize_expression::<C>(
                expr,
                buffer,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            )?;
            serialize_index(buffer, index, use_u8_index_for_fields)?;
        }
    }
    Ok(())
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

fn bytes_to_affines<C: CurveAffine>(bytes: &[u8]) -> bcs::Result<Vec<C>> {
    let point_size = 32; // bn256 G1Affine compressed format size
    if !bytes.len().is_multiple_of(point_size) {
        return Err(BcsError::Custom(format!(
            "Commitments bytes length not multiple of point size (expected multiple of {}, got {})",
            point_size,
            bytes.len()
        )));
    }

    let mut v = Vec::with_capacity(bytes.len() / point_size);
    for (i, chunk) in bytes.chunks(point_size).enumerate() {
        let mut repr = C::Repr::default();
        repr.as_mut().copy_from_slice(chunk);
        let point = C::from_bytes(&repr)
            .into_option()
            .ok_or_else(|| BcsError::Custom(format!("Invalid commitment point at index {}", i)))?;
        v.push(point);
    }
    Ok(v)
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

fn deserialize_expression<C: CurveAffine>(
    cursor: &mut Cursor<&[u8]>,
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<IndexedExpression<C::Scalar>> {
    let tag = cursor
        .read_u8()
        .map_err(|e| BcsError::Custom(e.to_string()))?;

    match tag {
        0x00 => {
            let idx = if use_u8_fields {
                IndexType::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                IndexType::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::ConstantIndex(idx, PhantomData))
        }
        0x02 => {
            let idx = if use_u8_query {
                IndexType::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                IndexType::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Fixed(idx))
        }
        0x03 => {
            let idx = if use_u8_query {
                IndexType::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                IndexType::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Advice(idx))
        }
        0x04 => {
            let idx = if use_u8_query {
                IndexType::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                IndexType::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Instance(idx))
        }
        0x05 => {
            let idx = cursor
                .read_u32::<LittleEndian>()
                .map_err(|e| BcsError::Custom(e.to_string()))?;
            if idx as usize >= challenge_phase.len() {
                return Err(BcsError::Custom(format!(
                    "Challenge index {} out of bounds",
                    idx
                )));
            }
            let phase = challenge_phase[idx as usize];
            Ok(IndexedExpression::Challenge(Challenge {
                index: idx as usize,
                phase,
            }))
        }
        0x06 => {
            let inner =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            Ok(IndexedExpression::Negated(Box::new(inner)))
        }
        0x07 => {
            let a =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            let b =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            Ok(IndexedExpression::Sum(Box::new(a), Box::new(b)))
        }
        0x08 => {
            let a =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            let b =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            Ok(IndexedExpression::Product(Box::new(a), Box::new(b)))
        }
        0x09 => {
            let expr =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            let idx = if use_u8_fields {
                IndexType::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                IndexType::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Scaled(Box::new(expr), idx))
        }
        _ => Err(BcsError::Custom(format!(
            "Unknown expression tag: 0x{:02x}",
            tag
        ))),
    }
}

fn deserialize_exprs<C: CurveAffine>(
    bytes: &[u8],
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<Vec<IndexedExpression<C::Scalar>>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut cursor = Cursor::new(bytes);
    let mut exprs = Vec::new();

    while cursor.position() < bytes.len() as u64 {
        let expr =
            deserialize_expression::<C>(&mut cursor, use_u8_fields, use_u8_query, challenge_phase)?;
        exprs.push(expr);
    }

    if cursor.position() as usize != bytes.len() {
        return Err(BcsError::Custom(
            "Trailing bytes in expression data".to_string(),
        ));
    }

    Ok(exprs)
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
