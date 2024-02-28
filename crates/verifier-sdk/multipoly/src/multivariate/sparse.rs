//! A sparse multivariate polynomial represented in coefficient form.
use crate::{
    multivariate::{SparseTerm, Term},
    DenseMVPolynomial, Polynomial,
};
use halo2_base::halo2_proofs::arithmetic::Field;
use num_traits::Zero;
//use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::ops::{Deref, Mul, MulAssign};
use std::{
    cmp::Ordering,
    fmt,
    ops::{Add, AddAssign, Neg, Sub, SubAssign},
    vec::Vec,
};

use derivative::Derivative;

/// Stores a sparse multivariate polynomial in coefficient form.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Default)]
pub struct SparsePolynomial<F: Field, T: Term> {
    /// The number of variables the polynomial supports
    #[derivative(PartialEq = "ignore")]
    pub num_vars: usize,
    /// List of each term along with its coefficient
    pub terms: Vec<(F, T)>,
}

impl<F: Field, T: Term> SparsePolynomial<F, T> {
    fn remove_zeros(&mut self) {
        self.terms.retain(|(c, _)| !bool::from(c.is_zero()));
    }
}

impl<F: Field + Ord> Polynomial<F> for SparsePolynomial<F, SparseTerm> {
    type Point = Vec<F>;

    /// Returns the total degree of the polynomial
    ///
    /// # Examples
    /// ```
    /// use ark_poly::{
    ///     polynomial::multivariate::{SparsePolynomial, SparseTerm},
    ///     DenseMVPolynomial, Polynomial,
    /// };
    /// use ark_std::test_rng;
    /// use ark_test_curves::bls12_381::Fq;
    ///
    /// let rng = &mut test_rng();
    /// // Create a multivariate polynomial of degree 7
    /// let poly: SparsePolynomial<Fq, SparseTerm> = SparsePolynomial::rand(7, 2, rng);
    /// assert_eq!(poly.degree(), 7);
    /// ```
    fn degree(&self) -> usize {
        self.terms
            .iter()
            .map(|(_, term)| term.degree())
            .max()
            .unwrap_or(0)
    }

    /// Evaluates `self` at the given `point` in `Self::Point`.
    ///
    /// # Examples
    /// ```
    /// use ark_ff::UniformRand;
    /// use ark_poly::{
    ///     polynomial::multivariate::{SparsePolynomial, SparseTerm, Term},
    ///     DenseMVPolynomial, Polynomial,
    /// };
    /// use ark_std::test_rng;
    /// use ark_test_curves::bls12_381::Fq;
    ///
    /// let rng = &mut test_rng();
    /// let poly = SparsePolynomial::rand(4, 3, rng);
    /// let random_point = vec![Fq::rand(rng); 3];
    /// // The result will be a single element in the field.
    /// let result: Fq = poly.evaluate(&random_point);
    /// ```
    fn evaluate(&self, point: &Vec<F>) -> F {
        assert!(point.len() >= self.num_vars, "Invalid evaluation domain");

        /*
        if self.is_zero() {
            return F::ZERO;
        }
        self.terms
            .iter()
            .map(|(coeff, term)| *coeff * term.evaluate(point))
            .sum()
         */

        return F::zero();
    }
}

impl<F: Field + Ord> DenseMVPolynomial<F> for SparsePolynomial<F, SparseTerm> {
    /// Returns the number of variables in `self`
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    // /// Outputs an `l`-variate polynomial which is the sum of `l` `d`-degree
    // /// univariate polynomials where each coefficient is sampled uniformly at random.
    // fn rand<R: Rng>(d: usize, l: usize, rng: &mut R) -> Self {
    //     let mut random_terms = vec![(F::random(rng), SparseTerm::new(vec![]))];
    //     for var in 0..l {
    //         for deg in 1..=d {
    //             random_terms.push((F::random(rng), SparseTerm::new(vec![(var, deg)])));
    //         }
    //     }
    //     Self::from_coefficients_vec(l, random_terms)
    // }
    //
    type Term = SparseTerm;

    /// Constructs a new polynomial from a list of tuples of the form `(coeff, Self::Term)`
    ///
    /// # Examples
    /// ```
    /// use ark_poly::{
    ///     polynomial::multivariate::{SparsePolynomial, SparseTerm, Term},
    ///     DenseMVPolynomial, Polynomial,
    /// };
    /// use ark_test_curves::bls12_381::Fq;
    ///
    /// // Create a multivariate polynomial in 3 variables, with 4 terms:
    /// // 2*x_0^3 + x_0*x_2 + x_1*x_2 + 5
    /// let poly = SparsePolynomial::from_coefficients_vec(
    ///     3,
    ///     vec![
    ///         (Fq::from(2), SparseTerm::new(vec![(0, 3)])),
    ///         (Fq::from(1), SparseTerm::new(vec![(0, 1), (2, 1)])),
    ///         (Fq::from(1), SparseTerm::new(vec![(1, 1), (2, 1)])),
    ///         (Fq::from(5), SparseTerm::new(vec![])),
    ///     ],
    /// );
    /// ```
    fn from_coefficients_vec(num_vars: usize, mut terms: Vec<(F, SparseTerm)>) -> Self {
        // Ensure that terms are in ascending order.
        terms.sort_by(|(_, t1), (_, t2)| t1.cmp(t2));
        // If any terms are duplicated, add them together
        let mut terms_dedup: Vec<(F, SparseTerm)> = Vec::new();
        for term in terms {
            if let Some(prev) = terms_dedup.last_mut() {
                if prev.1 == term.1 {
                    *prev = (prev.0 + term.0, prev.1.clone());
                    continue;
                }
            };
            // Assert correct number of indeterminates
            assert!(
                term.1.iter().all(|(var, _)| *var < num_vars),
                "Invalid number of indeterminates"
            );
            terms_dedup.push(term);
        }
        let mut result = Self {
            num_vars,
            terms: terms_dedup,
        };
        // Remove any terms with zero coefficients
        result.remove_zeros();
        result
    }

    /// Returns the terms of a `self` as a list of tuples of the form `(coeff, Self::Term)`
    fn terms(&self) -> &[(F, Self::Term)] {
        self.terms.as_slice()
    }
}

impl<F: Field, T: Term> Add for SparsePolynomial<F, T> {
    type Output = SparsePolynomial<F, T>;

    fn add(self, other: SparsePolynomial<F, T>) -> Self {
        &self + &other
    }
}

impl<'a, 'b, F: Field, T: Term> Add<&'a SparsePolynomial<F, T>> for &'b SparsePolynomial<F, T> {
    type Output = SparsePolynomial<F, T>;

    fn add(self, other: &'a SparsePolynomial<F, T>) -> SparsePolynomial<F, T> {
        let mut result = Vec::new();
        let mut cur_iter = self.terms.iter().peekable();
        let mut other_iter = other.terms.iter().peekable();
        // Since both polynomials are sorted, iterate over them in ascending order,
        // combining any common terms
        loop {
            // Peek at iterators to decide which to take from
            let which = match (cur_iter.peek(), other_iter.peek()) {
                (Some(cur), Some(other)) => Some((cur.1).cmp(&other.1)),
                (Some(_), None) => Some(Ordering::Less),
                (None, Some(_)) => Some(Ordering::Greater),
                (None, None) => None,
            };
            // Push the smallest element to the `result` coefficient vec
            let smallest = match which {
                Some(Ordering::Less) => cur_iter.next().unwrap().clone(),
                Some(Ordering::Equal) => {
                    let other = other_iter.next().unwrap();
                    let cur = cur_iter.next().unwrap();
                    (cur.0 + other.0, cur.1.clone())
                }
                Some(Ordering::Greater) => other_iter.next().unwrap().clone(),
                None => break,
            };
            result.push(smallest);
        }
        // Remove any zero terms
        result.retain(|(c, _)| !bool::from(c.is_zero()));
        SparsePolynomial {
            num_vars: core::cmp::max(self.num_vars, other.num_vars),
            terms: result,
        }
    }
}

impl<'a, F: Field, T: Term> AddAssign<&'a SparsePolynomial<F, T>> for SparsePolynomial<F, T> {
    fn add_assign(&mut self, other: &'a SparsePolynomial<F, T>) {
        *self = &*self + other;
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<'a, F: Field, T: Term> AddAssign<(F, &'a SparsePolynomial<F, T>)> for SparsePolynomial<F, T> {
    fn add_assign(&mut self, (f, other): (F, &'a SparsePolynomial<F, T>)) {
        let other = Self {
            num_vars: other.num_vars,
            terms: other
                .terms
                .iter()
                .map(|(coeff, term)| (*coeff * f, term.clone()))
                .collect(),
        };
        // Note the call to `Add` will remove also any duplicates
        *self = &*self + &other;
    }
}

impl<F: Field, T: Term> Neg for SparsePolynomial<F, T> {
    type Output = SparsePolynomial<F, T>;

    #[inline]
    fn neg(mut self) -> SparsePolynomial<F, T> {
        for coeff in &mut self.terms {
            (coeff).0 = -coeff.0;
        }
        self
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b, F: Field, T: Term> Sub<&'a SparsePolynomial<F, T>> for &'b SparsePolynomial<F, T> {
    type Output = SparsePolynomial<F, T>;

    #[inline]
    fn sub(self, other: &'a SparsePolynomial<F, T>) -> SparsePolynomial<F, T> {
        let neg_other = other.clone().neg();
        self + &neg_other
    }
}

impl<'a, F: Field, T: Term> SubAssign<&'a SparsePolynomial<F, T>> for SparsePolynomial<F, T> {
    #[inline]
    fn sub_assign(&mut self, other: &'a SparsePolynomial<F, T>) {
        *self = &*self - other;
    }
}

impl<F: Field, T: Term> fmt::Debug for SparsePolynomial<F, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for (coeff, term) in self.terms.iter().filter(|(c, _)| !bool::from(c.is_zero())) {
            if term.is_constant() {
                write!(f, "\n{:?}", coeff)?;
            } else {
                write!(f, "\n{:?} {:?}", coeff, term)?;
            }
        }
        Ok(())
    }
}

impl<F: Field, T: Term> Zero for SparsePolynomial<F, T> {
    /// Returns the zero polynomial.
    fn zero() -> Self {
        Self {
            num_vars: 0,
            terms: Vec::new(),
        }
    }

    /// Checks if the given polynomial is zero.
    fn is_zero(&self) -> bool {
        self.terms.is_empty() || self.terms.iter().all(|(c, _)| c.is_zero().into())
    }
}

impl<'a, 'b, F: Field + Ord> Mul<&'a SparsePolynomial<F, SparseTerm>>
    for &'b SparsePolynomial<F, SparseTerm>
{
    type Output = SparsePolynomial<F, SparseTerm>;

    /// Perform a naive n^2 multiplication of `self` by `other`.
    #[inline]
    fn mul(self, other: &'a SparsePolynomial<F, SparseTerm>) -> SparsePolynomial<F, SparseTerm> {
        if self.is_zero() || other.is_zero() {
            SparsePolynomial::zero()
        } else {
            let mut result_terms = Vec::new();
            for (cur_coeff, cur_term) in self.terms.iter() {
                for (other_coeff, other_term) in other.terms.iter() {
                    let mut term = cur_term.deref().to_vec();
                    term.extend(other_term.deref());
                    result_terms.push((*cur_coeff * *other_coeff, SparseTerm::new(term)));
                }
            }
            SparsePolynomial::from_coefficients_vec(self.num_vars, result_terms)
        }
    }
}

impl<'a, F: Field + Ord, T: Term> Mul<&'a F> for SparsePolynomial<F, T> {
    type Output = SparsePolynomial<F, T>;

    /// Perform a naive n^2 multiplication of `self` by `other`.
    #[inline]
    fn mul(mut self, other: &'a F) -> SparsePolynomial<F, T> {
        self *= other;
        self
    }
}

impl<'a, F: Field + Ord, T: Term> MulAssign<&'a F> for SparsePolynomial<F, T> {
    #[inline]
    fn mul_assign(&mut self, other: &'a F) {
        if self.is_zero() || bool::from(other.is_zero()) {
            *self = SparsePolynomial::zero();
        } else {
            self.terms.iter_mut().for_each(|(coeff, _)| *coeff *= other);
        }
    }
}
