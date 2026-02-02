use circuit_info::CircuitInfo;
use circuit_info::{ColumnQuery, Gate, Lookup, Rotation, Shuffle};
use expression::{to_indexed_expression, IndexedExpression};
use halo2_backend::plonk::{
    ConstraintSystemBack as ConstraintSystem, ExpressionBack as Expression, GateBack,
    LookupArgumentBack, PermutationArgumentBack, QueryBack, ShuffleArgumentBack, VarBack,
};
use halo2_middleware::circuit::ColumnMid;
use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::halo2curves::ff::FromUniformBytes;
use halo2_proofs::plonk::{keygen_vk, Any, Circuit, Error, ErrorFront};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation as Halo2Rotation;
use helpers::encode_field;
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;

pub(crate) mod circuit_info;
mod expression;
mod helpers;

// Custom serialization for the Halo2 circuit environment, where all field elements
// are replaced with indices pointing to a constant table.

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

fn halo2_rotation_from_custom(rotation: &Rotation) -> Halo2Rotation {
    let rot_val = rotation.rotation as i32;
    if rotation.next {
        Halo2Rotation(rot_val)
    } else {
        Halo2Rotation(-rot_val)
    }
}

fn any_from_type(column_type: u8) -> Result<Any, Error> {
    match column_type {
        1 => Ok(Any::Advice),
        2 => Ok(Any::Fixed),
        3 => Ok(Any::Instance),
        _ => Err(ErrorFront::Other("Invalid index for column type".to_string()).into()),
    }
}

// Reconstruct Expression from IndexedExpression
fn reconstruct_expression<C: CurveAffine>(
    indexed: &IndexedExpression<C::Scalar>,
    cs: &ConstraintSystem<C::Scalar>,
    fields_pool: &[C::Scalar],
) -> Result<Expression<C::Scalar>, Error> {
    match indexed {
        IndexedExpression::ConstantIndex(idx, _) => {
            let i = idx.value() as usize;
            if i >= fields_pool.len() {
                return Err(ErrorFront::Other("Constant index out of bounds".to_string()).into());
            }
            Ok(Expression::Constant(fields_pool[i]))
        }
        IndexedExpression::Fixed(idx) => {
            let i = idx.value() as usize;
            if i >= cs.fixed_queries.len() {
                return Err(
                    ErrorFront::Other("Fixed query index out of bounds".to_string()).into(),
                );
            }
            let (col, rot) = cs.fixed_queries[i];
            Ok(Expression::Var(VarBack::Query(QueryBack {
                index: i,
                column_index: col.index,
                column_type: col.column_type,
                rotation: rot,
            })))
        }
        IndexedExpression::Advice(idx) => {
            let i = idx.value() as usize;
            if i >= cs.advice_queries.len() {
                return Err(
                    ErrorFront::Other("Advice query index out of bounds".to_string()).into(),
                );
            }
            let (col, rot) = cs.advice_queries[i];
            Ok(Expression::Var(VarBack::Query(QueryBack {
                index: i,
                column_index: col.index,
                column_type: col.column_type,
                rotation: rot,
            })))
        }
        IndexedExpression::Instance(idx) => {
            let i = idx.value() as usize;
            if i >= cs.instance_queries.len() {
                return Err(
                    ErrorFront::Other("Instance query index out of bounds".to_string()).into(),
                );
            }
            let (col, rot) = cs.instance_queries[i];
            Ok(Expression::Var(VarBack::Query(QueryBack {
                index: i,
                column_index: col.index,
                column_type: col.column_type,
                rotation: rot,
            })))
        }
        IndexedExpression::Challenge(ch) => Ok(Expression::Var(VarBack::Challenge(*ch))),
        IndexedExpression::Negated(child) => Ok(Expression::Negated(Box::new(
            reconstruct_expression::<C>(child, cs, fields_pool)?,
        ))),
        IndexedExpression::Sum(a, b) => Ok(Expression::Sum(
            Box::new(reconstruct_expression::<C>(a, cs, fields_pool)?),
            Box::new(reconstruct_expression::<C>(b, cs, fields_pool)?),
        )),
        IndexedExpression::Product(a, b) => Ok(Expression::Product(
            Box::new(reconstruct_expression::<C>(a, cs, fields_pool)?),
            Box::new(reconstruct_expression::<C>(b, cs, fields_pool)?),
        )),
        IndexedExpression::Scaled(child, idx) => {
            let i = idx.value() as usize;
            if i >= fields_pool.len() {
                return Err(
                    ErrorFront::Other("Scaled constant index out of bounds".to_string()).into(),
                );
            }
            let scalar = fields_pool[i];
            let child_expr = reconstruct_expression::<C>(child, cs, fields_pool)?;

            Ok(Expression::Product(
                Box::new(child_expr),
                Box::new(Expression::Constant(scalar)),
            ))
        }
    }
}

// Generate CircuitInfo containing compressed information of a given circuit.
pub(crate) fn generate_circuit_info<C, P, ConcreteCircuit>(
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

// Reconstruct ConstraintSystem from CircuitInfo
pub(crate) fn reconstruct_cs_from_circuit_info<C: CurveAffine>(
    info: &CircuitInfo<C>,
) -> Result<ConstraintSystem<C::Scalar>, Error>
where
    C::Scalar: Field,
{
    // 1. Infer num_advice_columns from advice_queries (max column index + 1)
    let num_advice_columns = if info.advice_queries.is_empty() {
        0
    } else {
        info.advice_queries
            .iter()
            .map(|q| q.column.index as usize)
            .max()
            .ok_or(Error::Frontend(ErrorFront::Other(
                "failed to infer num_advice_columns".to_string(),
            )))?
            + 1
    };

    // 2. Create empty ConstraintSystem
    let mut cs = ConstraintSystem::<C::Scalar> {
        num_fixed_columns: info.num_fixed_columns as usize,
        num_advice_columns,
        num_instance_columns: info.num_instance_columns as usize,
        num_challenges: info.challenge_phase.len(),
        unblinded_advice_columns: Vec::new(),
        advice_column_phase: info.advice_column_phase.clone(),
        challenge_phase: info.challenge_phase.clone(),
        gates: Vec::new(),
        advice_queries: Vec::new(),
        num_advice_queries: vec![0; num_advice_columns],
        instance_queries: Vec::new(),
        fixed_queries: Vec::new(),
        permutation: PermutationArgumentBack {
            columns: Vec::new(),
        },
        lookups: Vec::new(),
        shuffles: Vec::new(),
        minimum_degree: None,
    };

    // 3. Fill queries and num_advice_queries
    for q in &info.advice_queries {
        let column_type = any_from_type(q.column.column_type)?;
        let col = ColumnMid {
            index: q.column.index as usize,
            column_type,
        };
        let rot = halo2_rotation_from_custom(&q.rotation);
        cs.advice_queries.push((col, rot));
        if col.column_type == Any::Advice {
            cs.num_advice_queries[col.index] += 1;
        }
    }

    for q in &info.instance_queries {
        let column_type = any_from_type(q.column.column_type)?;
        let col = ColumnMid {
            index: q.column.index as usize,
            column_type,
        };
        let rot = halo2_rotation_from_custom(&q.rotation);
        cs.instance_queries.push((col, rot));
    }

    for q in &info.fixed_queries {
        let column_type = any_from_type(q.column.column_type)?;
        let col = ColumnMid {
            index: q.column.index as usize,
            column_type,
        };
        let rot = halo2_rotation_from_custom(&q.rotation);
        cs.fixed_queries.push((col, rot));
    }

    // 4. Fill permutation columns
    cs.permutation.columns = info
        .permutation_columns
        .iter()
        .map(|c| {
            let column_type = any_from_type(c.column_type)?;
            Ok::<_, Error>(ColumnMid {
                index: c.index as usize,
                column_type,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 5. Reconstruct gates (now that queries are filled)
    for gate in &info.gates {
        let polys = gate
            .polys
            .iter()
            .map(|e| reconstruct_expression::<C>(e, &cs, &info.fields_pool))
            .collect::<Result<Vec<_>, _>>()?;
        if polys.is_empty() {
            return Err(ErrorFront::Other("Gate with no polynomials".to_string()).into());
        }
        // For now, we only support single polynomial gates
        cs.gates.push(GateBack {
            name: "unknown".to_string(),
            poly: polys[0].clone(),
        });
    }

    // 6. Reconstruct lookups
    for lookup in &info.lookups {
        let input_expressions = lookup
            .input_exprs
            .iter()
            .map(|e| reconstruct_expression::<C>(e, &cs, &info.fields_pool))
            .collect::<Result<Vec<_>, _>>()?;
        let table_expressions = lookup
            .table_exprs
            .iter()
            .map(|e| reconstruct_expression::<C>(e, &cs, &info.fields_pool))
            .collect::<Result<Vec<_>, _>>()?;
        cs.lookups.push(LookupArgumentBack {
            name: "unknown".to_string(),
            input_expressions,
            table_expressions,
        });
    }

    // 7. Reconstruct shuffles (similar to lookups)
    for shuffle in &info.shuffles {
        let input_expressions = shuffle
            .input_exprs
            .iter()
            .map(|e| reconstruct_expression::<C>(e, &cs, &info.fields_pool))
            .collect::<Result<Vec<_>, _>>()?;
        let shuffle_expressions = shuffle
            .shuffle_exprs
            .iter()
            .map(|e| reconstruct_expression::<C>(e, &cs, &info.fields_pool))
            .collect::<Result<Vec<_>, _>>()?;
        cs.shuffles.push(ShuffleArgumentBack {
            name: "unknown".to_string(),
            input_expressions,
            shuffle_expressions,
        });
    }

    // Optional: Set minimum_degree based on cs_degree if needed
    // cs.minimum_degree = Some(info.cs_degree as usize);

    Ok(cs)
}

/// Generate serialized protocol for the halo2 move verifier.
pub fn generate_serialized_protocol<C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
) -> Result<Vec<Vec<Vec<u8>>>, Error>
where
    C: CurveAffine,
    P: Params<C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: FromUniformBytes<64>,
    C::ScalarExt: FromUniformBytes<64>,
{
    let info = generate_circuit_info(params, circuit)?;
    info.serialize()
        .map_err(|e| ErrorFront::Other(format!("CircuitInfo serialization failed: {e}")).into())
}

/// Generate serialized circuit for the native verifier.
pub fn generate_serialized_circuit<C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
) -> Result<Vec<u8>, Error>
where
    C: CurveAffine,
    P: Params<C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: FromUniformBytes<64>,
    C::ScalarExt: FromUniformBytes<64>,
{
    let info = generate_circuit_info(params, circuit)?;
    info.to_bytes()
        .map_err(|e| ErrorFront::Other(format!("CircuitInfo serialization failed: {e}")).into())
}

/// Reconstruct ConstraintSystem from serialized circuit bytes.
pub fn reconstruct_cs_from_circuit_bytes<C: CurveAffine>(
    circuit_info_bytes: &[u8],
) -> Result<ConstraintSystem<C::Scalar>, Error>
where
    C::Scalar: Field,
{
    let circuit_info = CircuitInfo::<C>::from_bytes(circuit_info_bytes)
        .map_err(|e| ErrorFront::Other(format!("Circuit info deserialization failed: {e}")))?;
    reconstruct_cs_from_circuit_info::<C>(&circuit_info)
}
