pub mod serialize;

use std::collections::BTreeMap;

use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::halo2curves::ff::FromUniformBytes;
use halo2_proofs::plonk::{
    keygen_vk, Any, Circuit, ConstraintSystem, Error, Expression, Fixed, Instance,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation as Halo2Rotation;

use multipoly::multivariate::{SparsePolynomial, SparseTerm, Term};
use multipoly::DenseMVPolynomial;

#[derive(Debug)]
pub struct CircuitInfo<C: CurveAffine> {
    vk_transcript_repr: C::Scalar,
    fixed_commitments: Vec<C>,
    permutation_commitments: Vec<C>,

    query_instance: bool,
    k: u8,
    max_num_query_of_advice_column: u32,
    cs_degree: u32,
    num_fixed_columns: u64,
    num_instance_columns: u64,
    advice_column_phase: Vec<u8>,
    challenge_phase: Vec<u8>,
    gates: Vec<Vec<MultiVariatePolynomial<C::Scalar>>>,

    advice_queries: Vec<ColumnQuery>,
    instance_queries: Vec<ColumnQuery>,
    fixed_queries: Vec<ColumnQuery>,
    permutation_columns: Vec<Column>,
    lookups: Vec<Lookup<C::Scalar>>,
}

#[derive(Debug)]
pub struct ColumnQuery {
    pub column: Column,
    pub rotation: Rotation,
}
#[derive(Debug)]
pub struct Column {
    pub index: u32,
    pub column_type: u8,
}

impl From<halo2_proofs::plonk::Column<Any>> for Column {
    fn from(value: halo2_proofs::plonk::Column<Any>) -> Self {
        let column_type = match value.column_type() {
            Any::Advice(phase) => phase.phase(),
            Any::Fixed => 255,
            Any::Instance => 244,
        };
        Column {
            index: value.index() as u32,
            column_type,
        }
    }
}

#[derive(Debug)]
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
#[derive(Debug)]
pub struct Lookup<F: Field> {
    pub input_exprs: Vec<MultiVariatePolynomial<F>>,
    pub table_exprs: Vec<MultiVariatePolynomial<F>>,
}

pub type MultiVariatePolynomial<F> = SparsePolynomial<F, SparseTerm>;

pub fn generate_circuit_info<'params, C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
) -> Result<CircuitInfo<C>, Error>
where
    C: CurveAffine,
    P: Params<'params, C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: FromUniformBytes<64>,
    C::ScalarExt: FromUniformBytes<64>,
{
    let vk = keygen_vk(params, circuit)?;
    let cs = vk.cs();
    // as halo2 dones'nt expose vk's transcript_repr,
    // we had to copy the code here.
    let vk_repr = {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", vk.pinned());

        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        // Hash in final Blake2bState
        C::Scalar::from_uniform_bytes(hasher.finalize().as_array())
    };

    let info = CircuitInfo {
        vk_transcript_repr: vk_repr,
        fixed_commitments: vk.fixed_commitments().clone(),
        permutation_commitments: vk.permutation().commitments().clone(),
        query_instance: false,
        k: (params.k() as u8), // we expect k would not be too large.
        cs_degree: cs.degree() as u32,
        num_fixed_columns: cs.num_fixed_columns() as u64,
        num_instance_columns: cs.num_instance_columns() as u64,
        advice_column_phase: cs.advice_column_phase(),
        challenge_phase: cs.challenge_phase(),

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
            .get_columns()
            .iter()
            .map(|c| From::from(*c))
            .collect(),
        lookups: cs
            .lookups()
            .iter()
            .map(|l| Lookup {
                input_exprs: l
                    .input_expressions()
                    .iter()
                    .map(|e| {
                        expression_transform(
                            cs,
                            e,
                            cs.advice_queries().len(),
                            cs.fixed_queries().len(),
                            cs.instance_queries().len(),
                            cs.challenge_phase().len(),
                        )
                    })
                    .collect(),
                table_exprs: l
                    .table_expressions()
                    .iter()
                    .map(|e| {
                        expression_transform(
                            cs,
                            e,
                            cs.advice_queries().len(),
                            cs.fixed_queries().len(),
                            cs.instance_queries().len(),
                            cs.challenge_phase().len(),
                        )
                    })
                    .collect(),
            })
            .collect(),
        max_num_query_of_advice_column: cs
            .advice_queries()
            .iter()
            .fold(BTreeMap::default(), |mut m, (c, _r)| {
                if let std::collections::btree_map::Entry::Vacant(e) = m.entry(c.index()) {
                    e.insert(1u32);
                } else {
                    *m.get_mut(&c.index()).unwrap() += 1;
                }
                m
            })
            .values()
            .max()
            .cloned()
            .unwrap_or_default(),

        gates: cs
            .gates()
            .iter()
            .map(|g| {
                g.polynomials()
                    .iter()
                    .map(|e| {
                        expression_transform(
                            cs,
                            e,
                            cs.advice_queries().len(),
                            cs.fixed_queries().len(),
                            cs.instance_queries().len(),
                            cs.challenge_phase().len(),
                        )
                    })
                    .collect()
            })
            .collect(),
    };
    Ok(info)
}

/// basicly, we treat every queries and challenges as a variable, so there will be `advice_queries_len+fixed_queries_len+instance_queries_len+challenges_len` variables.
/// and the orders should be the same as that in `expression.move`.
fn expression_transform<F: Field + Ord>(
    cs: &ConstraintSystem<F>,
    expr: &Expression<F>,
    advice_queries_len: usize,
    fixed_queries_len: usize,
    instance_queries_len: usize,
    challenges_len: usize,
) -> SparsePolynomial<F, SparseTerm> {
    let advice_range = advice_queries_len;
    let fixed_range = advice_range + fixed_queries_len;
    let instance_range = fixed_range + instance_queries_len;
    let challenge_range = instance_range + challenges_len;

    expr.evaluate(
        &|c| {
            SparsePolynomial::from_coefficients_vec(
                challenge_range,
                vec![(c, SparseTerm::default())],
            )
        },
        &|_| panic!("virtual selectors are removed during optimization"),
        &|query| {
            let query_index = get_fixed_query_index(cs, query.column_index(), query.rotation());
            SparsePolynomial::from_coefficients_vec(
                challenge_range,
                vec![(
                    F::ONE,
                    SparseTerm::new(vec![(advice_range + query_index, 1)]),
                )],
            )
        },
        &|query| {
            let query_index =
                get_advice_query_index(cs, query.column_index(), query.phase(), query.rotation());
            SparsePolynomial::from_coefficients_vec(
                challenge_range,
                vec![(F::ONE, SparseTerm::new(vec![(query_index, 1)]))],
            )
        },
        &|query| {
            let query_index = get_instance_query_index(cs, query.column_index(), query.rotation());
            SparsePolynomial::from_coefficients_vec(
                challenge_range,
                vec![(
                    F::ONE,
                    SparseTerm::new(vec![(fixed_range + query_index, 1)]),
                )],
            )
        },
        &|challenge| {
            SparsePolynomial::from_coefficients_vec(
                challenge_range,
                vec![(
                    F::ONE,
                    SparseTerm::new(vec![(instance_range + challenge.index(), 1)]),
                )],
            )
        },
        &|a| -a,
        &|a, b| a + b,
        &|a, b| &a * &b,
        &|a, scalar| a * &scalar,
    )
}

/// because halo2 doesn't expose these function, we had to copy them here.
/// TODO; pr to halo2 to expose these functions
pub(crate) fn get_advice_query_index<F: Field>(
    cs: &ConstraintSystem<F>,
    column_index: usize,
    phase: u8,
    at: Halo2Rotation,
) -> usize {
    for (index, (query_column, rotation)) in cs.advice_queries().iter().enumerate() {
        if (
            query_column.index(),
            query_column.column_type().phase(),
            rotation,
        ) == (column_index, phase, &at)
        {
            return index;
        }
    }

    panic!("get_advice_query_index called for non-existent query");
}

pub(crate) fn get_fixed_query_index<F: Field>(
    cs: &ConstraintSystem<F>,
    column_index: usize,
    at: Halo2Rotation,
) -> usize {
    for (index, (query_column, rotation)) in cs.fixed_queries().iter().enumerate() {
        if (query_column.index(), query_column.column_type(), rotation)
            == (column_index, &Fixed, &at)
        {
            return index;
        }
    }

    panic!("get_fixed_query_index called for non-existent query");
}

pub(crate) fn get_instance_query_index<F: Field>(
    cs: &ConstraintSystem<F>,
    column_index: usize,
    at: Halo2Rotation,
) -> usize {
    for (index, (query_column, rotation)) in cs.instance_queries().iter().enumerate() {
        if (query_column.index(), query_column.column_type(), rotation)
            == (column_index, &Instance, &at)
        {
            return index;
        }
    }

    panic!("get_instance_query_index called for non-existent query");
}
