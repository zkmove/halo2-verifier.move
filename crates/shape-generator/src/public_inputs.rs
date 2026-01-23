use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::PrimeField;

#[derive(Clone)]
pub struct PublicInputs<C: CurveAffine>(Vec<Vec<C::Scalar>>);

impl<C: CurveAffine> PublicInputs<C> {
    pub fn to_bytes(&self) -> Vec<Vec<Vec<u8>>> {
        self.0
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|scalar| scalar.to_repr().as_ref().to_vec())
                    .collect()
            })
            .collect()
    }

    pub fn from_bytes(bytes: &[Vec<Vec<u8>>]) -> Result<Self, String> {
        let mut columns = Vec::with_capacity(bytes.len());
        for column_bytes in bytes {
            let mut column = Vec::with_capacity(column_bytes.len());
            for scalar_bytes in column_bytes {
                let mut repr = <C::Scalar as PrimeField>::Repr::default();
                if scalar_bytes.len() != repr.as_ref().len() {
                    return Err("Invalid byte length".to_string());
                }
                repr.as_mut().copy_from_slice(scalar_bytes);
                let scalar = <C::Scalar as PrimeField>::from_repr(repr)
                    .into_option()
                    .ok_or("Invalid field element")?;
                column.push(scalar);
            }
            columns.push(column);
        }
        Ok(PublicInputs(columns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::arithmetic::Field;
    use halo2curves::bn256::{Fr, G1Affine};
    use rand::rngs::OsRng;

    #[test]
    fn test_to_bytes_and_from_bytes() {
        let num_columns = 4;
        let num_rows = 3;
        let mut columns = (0..num_columns).map(|_| Vec::with_capacity(num_rows)).collect::<Vec<_>>();
        for col in &mut columns {
            for _ in 0..num_rows {
                col.push(Fr::random(OsRng));
            }
        }
        let public_inputs = PublicInputs::<G1Affine>(columns);

        let bytes = public_inputs.to_bytes();
        let restored = PublicInputs::<G1Affine>::from_bytes(&bytes).unwrap();

        assert_eq!(public_inputs.0, restored.0);
    }
}
