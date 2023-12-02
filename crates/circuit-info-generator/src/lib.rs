use std::collections::BTreeMap;

use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::halo2curves::ff::FromUniformBytes;
use halo2_proofs::plonk::{Any, Circuit, Error, Expression, keygen_vk};
use halo2_proofs::poly::commitment::Params;

use multipoly::DenseMVPolynomial;
use multipoly::multivariate::{SparsePolynomial, SparseTerm, Term};

pub struct CircuitInfo<F: Field> {
    query_instance: bool,
    k: u32,
    cs_degree: u64,
    num_fixed_columns: u64,
    num_instance_columns: u64,
    advice_column_phase: Vec<u8>,
    challenge_phase: Vec<u8>,
    gates: Vec<Vec<Expression<F>>>,

    advice_queries: Vec<ColumnQuery>,
    instance_queries: Vec<ColumnQuery>,
    fixed_queries: Vec<ColumnQuery>,
    permutation_columns: Vec<Column>,
    lookups: Vec<Lookup<F>>,
    max_num_query_of_advice_column: u32,
}


pub struct ColumnQuery {
    pub column: Column,
    pub rotation: Rotation,
}

pub struct Column {
    pub index: u32,
    pub column_type: u8,
}

impl From<halo2_proofs::plonk::Column<Any>> for Column {
    fn from(value: halo2_proofs::plonk::Column<Any>) -> Self {
        let column_type = match value.column_type() {
            Any::Advice(phase) => {
                phase.phase()
            }
            Any::Fixed => {
                255
            }
            Any::Instance => {
                244
            }
        };
        Column {
            index: value.index() as u32,
            column_type,
        }
    }
}

pub struct Rotation {
    pub rotation: u32,
    pub next: bool,
}

impl From<halo2_proofs::poly::Rotation> for Rotation {
    fn from(value: halo2_proofs::poly::Rotation) -> Self {
        if value.0.is_negative() {
            Self {
                rotation: value.0.abs() as u32,
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

pub struct Lookup<F: Field> {
    pub input_exprs: Vec<Expression<F>>,
    pub table_exprs: Vec<Expression<F>>,
}

pub fn generate_circuit_info<'params, C, P, ConcreteCircuit>(
    params: &P,
    circuit: &ConcreteCircuit,
) -> Result<CircuitInfo<C::Scalar>, Error>
    where
        C: CurveAffine,
        P: Params<'params, C>,
        ConcreteCircuit: Circuit<C::Scalar>,
        C::Scalar: FromUniformBytes<64>,
        C::ScalarExt: FromUniformBytes<64>,
{
    let vk = keygen_vk(params, circuit)?;
    let cs = vk.cs();
    let info = CircuitInfo {
        query_instance: false,
        k: params.k(),
        cs_degree: cs.degree() as u64,
        num_fixed_columns: cs.num_fixed_columns() as u64,
        num_instance_columns: cs.num_instance_columns() as u64,
        advice_column_phase: cs.advice_column_phase(),
        challenge_phase: cs.challenge_phase(),

        advice_queries: cs.advice_queries().iter().map(|(c, r)| ColumnQuery {
            column: halo2_proofs::plonk::Column::<Any>::from(c.clone()).into(),
            rotation: From::from(r.clone()),
        }).collect(),
        instance_queries: cs.instance_queries().iter().map(|(c, r)| ColumnQuery {
            column: halo2_proofs::plonk::Column::<Any>::from(c.clone()).into(),
            rotation: From::from(r.clone()),
        }).collect(),
        fixed_queries: cs.fixed_queries().iter().map(|(c, r)| ColumnQuery {
            column: halo2_proofs::plonk::Column::<Any>::from(c.clone()).into(),
            rotation: From::from(r.clone()),
        }).collect(),
        permutation_columns: cs.permutation().get_columns().iter().map(|c| From::from(c.clone())).collect(),
        lookups: cs.lookups().iter().map(|l| Lookup { input_exprs: l.input_expressions().clone(), table_exprs: l.table_expressions().clone() }).collect(),
        max_num_query_of_advice_column: cs.advice_queries().iter().fold(BTreeMap::default(), |mut m, (c, _r)| {
            if m.contains_key(&c.index()) {
                *m.get_mut(&c.index()).unwrap() += 1;
            } else {
                m.insert(c.index(), 1u32);
            }
            m
        }).values().max().cloned().unwrap_or_default(),

        // TODO: transform the expressions into multivariate polys
        gates: cs.gates().iter().map(|g| g.polynomials().to_vec()).collect(),
    };
    Ok(info)
}

// todo
struct MultiVariatePoly {}

/// basicly, we treat every queries and challenges as a variable, so there will be `advice_queries_len+fixed_queries_len+instance_queries_len+challenges_len` variables.
/// and the orders should be the same as that in `expression.move`.
fn expression_transform<F: Field + Ord>(expr: &Expression<F>, advice_queries_len: usize, fixed_queries_len: usize, instance_queries_len: usize, challenges_len: usize) -> SparsePolynomial<F, SparseTerm> {
    // TODO: use evaluate function of expr to construct the poly.

    let advice_range = advice_queries_len;
    let fixed_range = advice_range + fixed_queries_len;
    let instance_range = fixed_range + instance_queries_len;
    let challenge_range = instance_range + challenges_len;

    expr.evaluate(
        &|c| SparsePolynomial::from_coefficients_vec(challenge_range, vec![(c, SparseTerm::default())]),
        &|_| panic!("virtual selectors are removed during optimization"),
        &|query| SparsePolynomial::from_coefficients_vec(challenge_range, vec![(F::ONE, SparseTerm::new(vec![(advice_range + query.index.unwrap(), 1)]))]),
        &|query| SparsePolynomial::from_coefficients_vec(challenge_range, vec![(F::ONE, SparseTerm::new(vec![(query.index.unwrap(), 1)]))]),
        &|query| SparsePolynomial::from_coefficients_vec(challenge_range, vec![(F::ONE, SparseTerm::new(vec![(fixed_range + query.index.unwrap(), 1)]))]),
        &|challenge| SparsePolynomial::from_coefficients_vec(challenge_range, vec![(F::ONE, SparseTerm::new(vec![(instance_range + challenge.index(), 1)]))]),
        &|a| -a,
        &|a, b| a + b,
        &|a, b| &a * &b,
        &|a, scalar| a * &scalar,
    )

}